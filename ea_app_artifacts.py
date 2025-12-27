# “Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement”;

"""
EA App Artifacts Volatility 3 Plugin
===================================

This Volatility 3 plugin extracts forensic artefacts from the EA App
(formerly Origin) processes in Windows memory images.

The plugin focuses on recovering memory-resident artefacts related to:
- OAuth authentication (access and refresh tokens)
- JWT bearer tokens (decoded without verification)
- EA account identity and user metadata
- Device and installation identifiers
- Game entitlement and launch metadata
- EA network endpoints and API URLs

Operation overview:
- Enumerates running processes
- Filters for EA-related executables
- Scans readable VAD regions using YARA rules
- Carves JSON objects from memory windows
- Extracts and categorizes relevant artefacts
- Outputs structured forensic results via TreeGrid

This plugin is intended for digital forensics and incident response (DFIR)
use cases involving EA App activity.
"""

import json
import yara
import re
import base64

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo


class EAAppArtifacts(interfaces.plugins.PluginInterface):
    """
    Volatility 3 plugin to extract EA App artefacts from Windows memory images.

    This plugin scans EA-related processes for authentication tokens,
    account data, device identifiers, game metadata, and network artefacts.
    It uses YARA-based memory scanning combined with JSON carving to recover
    structured data from process memory.

    Attributes:
        _required_framework_version (tuple):
            Minimum supported Volatility framework version.

        _version (tuple):
            Plugin version number.

        MAX_WINDOW (int):
            Maximum number of bytes read from each matching memory region
            for JSON carving.

        EA_PROCESS_NAMES (set):
            Executable names associated with the EA App ecosystem.

        ACCOUNT_KEYS (set):
            JSON keys related to EA account identity.

        DEVICE_KEYS (set):
            JSON keys related to device and installation identity.

        GAME_KEYS (set):
            JSON keys related to game entitlements and execution.

        EA_YARA_RULES (str):
            YARA rules used to detect EA-related artefacts in memory.
    """

    _required_framework_version = (2, 0, 0)
    _version = (4, 0, 1)

    MAX_WINDOW = 8192

    EA_PROCESS_NAMES = {
        "eadesktop.exe",
        "eaapp.exe",
        "eabackgroundservice.exe",
    }

    ACCOUNT_KEYS = {
        "userId", "pidId", "personaId", "originPersonaId",
        "displayName", "email", "country", "locale"
    }

    DEVICE_KEYS = {
        "deviceId", "machineId", "installationId",
        "hardwareId"
    }

    GAME_KEYS = {
        "gameId", "offerId", "entitlementId",
        "executablePath", "launchArgs", "isTrial", "licenseState"
    }

    EA_YARA_RULES = r"""
    rule EA_CORE_ARTIFACTS
    {
        strings:
            $access  = /"access_token"\s*:\s*"[A-Za-z0-9\-_\.]{20,}"/ nocase ascii
            $refresh = /"refresh_token"\s*:\s*"[A-Za-z0-9\-_\.]{20,}"/ nocase ascii
            $jwt     = /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/ ascii
            $bearer  = /Authorization:\s*Bearer\s+[A-Za-z0-9\-_\.]{20,}/ nocase ascii
            $ws      = /wss?:\/\/[^\s"]+ea\.com[^\s"]*/ nocase ascii
            $api     = /https:\/\/[^\s"]+ea\.com\/[^\s"]*/ nocase ascii
            $ipc     = "ipcRenderer" ascii nocase
            $node    = "node::Buffer" ascii nocase
        condition:
            any of them
    }
    """

    @classmethod
    def get_requirements(cls):
        """
        Define plugin requirements for Volatility.

        Returns:
            list:
                A list containing a ModuleRequirement for the Windows kernel,
                supporting Intel 32-bit and 64-bit architectures.
        """
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]

    # -------------------------------------------------------------

    def _compile_rules(self):
        """
        Compile embedded YARA rules used to detect EA artefacts in memory.

        Returns:
            yara.Rules:
                Compiled YARA ruleset.
        """
        return yara.compile(source=self.EA_YARA_RULES)

    def _is_ea_process(self, name):
        """
        Check whether a process name belongs to an EA App process.

        Args:
            name (str):
                Process image name.

        Returns:
            bool:
                True if the process is EA-related, False otherwise.
        """
        return name.lower() in self.EA_PROCESS_NAMES

    # -------------------------------------------------------------

    def _decode_jwt(self, token):
        """
        Decode a JSON Web Token (JWT) without signature verification.

        This method Base64URL-decodes the header and payload portions
        of the JWT. Signature validation is intentionally omitted for
        forensic inspection purposes.

        Args:
            token (str):
                JWT string.

        Returns:
            dict or None:
                Dictionary containing decoded 'header' and 'payload',
                or None if decoding fails.
        """
        try:
            header_b64, payload_b64, _ = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
            return {"header": header, "payload": payload}
        except Exception:
            return None

    # -------------------------------------------------------------

    def _carve_json_objects(self, data):
        """
        Carve JSON objects from a raw memory buffer.

        This performs a simple brace-based extraction and attempts
        to parse JSON dictionaries from memory.

        Args:
            data (bytes):
                Raw memory data.

        Returns:
            list:
                List of successfully parsed JSON dictionaries.
        """
        results = []
        for blob in re.findall(rb"\{.*?\}", data, re.DOTALL):
            try:
                parsed = json.loads(blob.decode(errors="ignore"))
                if isinstance(parsed, dict):
                    results.append(parsed)
            except Exception:
                continue
        return results

    # -------------------------------------------------------------

    def _scan_vads(self, context, proc, rules):
        """
        Scan readable VAD regions of a process using YARA rules.

        Args:
            context:
                Volatility context object.
            proc:
                Process object to scan.
            rules (yara.Rules):
                Compiled YARA rules.

        Yields:
            bytes:
                Raw memory data from matching VAD regions.
        """
        process_layer_name = proc.add_process_layer()
        layer = context.layers[process_layer_name]

        for vad in vadinfo.VadInfo.list_vads(proc):
            protection = vad.get_protection(vadinfo.PROTECT_FLAGS)
            if not protection.startswith("READ"):
                continue

            try:
                data = layer.read(vad.get_start(), vad.get_size(), pad=True)
            except exceptions.InvalidAddressException:
                continue

            for _ in rules.match(data=data):
                yield data

    # -------------------------------------------------------------

    def _generator(self):
        """
        Generate TreeGrid rows containing extracted EA artefacts.

        This method orchestrates process enumeration, memory scanning,
        JSON carving, artefact extraction, and record construction.

        Yields:
            tuple:
                TreeGrid-compatible rows with process metadata and
                JSON-encoded artefact categories.
        """
        context = self.context
        rules = self._compile_rules()

        for proc in pslist.PsList.list_processes(
            context,
            self.config["kernel"]
        ):
            proc_name = utility.array_to_string(proc.ImageFileName)
            if not self._is_ea_process(proc_name):
                continue

            for data in self._scan_vads(context, proc, rules):
                window = data[:self.MAX_WINDOW]
                json_objects = self._carve_json_objects(window)

                for obj in json_objects:
                    record = {
                        "oauth": {},
                        "account": {},
                        "device": {},
                        "game": {},
                        "network": {},
                        "jwt": {},
                    }

                    # OAuth tokens
                    if "access_token" in obj:
                        record["oauth"]["access_token"] = obj.get("access_token")
                        record["oauth"]["expires_in"] = obj.get("expires_in")

                    if "refresh_token" in obj:
                        record["oauth"]["refresh_token"] = obj.get("refresh_token")

                    # JWT decoding
                    for val in obj.values():
                        if isinstance(val, str) and val.startswith("eyJ"):
                            decoded = self._decode_jwt(val)
                            if decoded:
                                record["jwt"] = decoded

                    # Account metadata
                    for k in self.ACCOUNT_KEYS:
                        if k in obj:
                            record["account"][k] = obj[k]

                    # Device metadata
                    for k in self.DEVICE_KEYS:
                        if k in obj:
                            record["device"][k] = obj[k]

                    # Game metadata
                    for k in self.GAME_KEYS:
                        if k in obj:
                            record["game"][k] = obj[k]

                    # Network endpoints
                    for k in obj:
                        if isinstance(obj[k], str) and "ea.com" in obj[k]:
                            record["network"].setdefault(
                                "endpoints", []
                            ).append(obj[k])

                    if any(record.values()):
                        yield (
                            0,
                            (
                                proc_name,
                                proc.UniqueProcessId,
                                json.dumps(record["oauth"], ensure_ascii=False),
                                json.dumps(record["account"], ensure_ascii=False),
                                json.dumps(record["device"], ensure_ascii=False),
                                json.dumps(record["game"], ensure_ascii=False),
                                json.dumps(record["network"], ensure_ascii=False),
                                json.dumps(record["jwt"], ensure_ascii=False),
                            ),
                        )

    # -------------------------------------------------------------

    def run(self):
        """
        Execute the plugin and render results.

        Returns:
            renderers.TreeGrid:
                TreeGrid containing extracted EA App artefacts.
        """
        return renderers.TreeGrid(
            [
                ("Process", str),
                ("PID", int),
                ("OAuth", str),
                ("Account", str),
                ("Device", str),
                ("Game", str),
                ("Network", str),
                ("JWT", str),
            ],
            self._generator(),
        )
