# “Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement”;

"""
EA App Artifacts Volatility 3 Plugin
===================================

This Volatility 3 plugin extracts forensic artefacts from the EA App
(formerly Origin) processes in Windows memory images.

The plugin focuses on:
- OAuth tokens and JWTs
- Account, device, and game metadata
- EA network endpoints
- Electron / Node.js artefacts commonly found in EA App memory
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
    """

    # Minimum Volatility framework version required
    _required_framework_version = (2, 0, 0)

    # Plugin version
    _version = (4, 0, 1)

    # Maximum amount of data processed per hit (prevents runaway parsing)
    MAX_WINDOW = 8192

    # Chunk size used when scanning VAD memory regions
    VAD_CHUNK_SIZE = 0x4000  # 16 KB

    # Known EA App-related process names
    EA_PROCESS_NAMES = {
        "eadesktop.exe",
        "eaapp.exe",
        "eabackgroundservice.exe",
    }

    # Common EA account-related JSON keys
    ACCOUNT_KEYS = {
        "userId", "pidId", "personaId", "originPersonaId",
        "displayName", "email", "country", "locale"
    }

    # Device / installation identifiers
    DEVICE_KEYS = {
        "deviceId", "machineId", "installationId",
        "hardwareId"
    }

    # Game / entitlement metadata
    GAME_KEYS = {
        "gameId", "offerId", "entitlementId",
        "executablePath", "launchArgs", "isTrial", "licenseState"
    }

    # YARA rules used to detect EA App artefacts in memory
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

    # -------------------------------------------------------------

    @classmethod
    def get_requirements(cls):
        """
        Declare plugin requirements.

        This plugin requires access to the Windows kernel module
        in order to enumerate processes and VADs.
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
        Compile the embedded YARA rules.
        """
        return yara.compile(source=self.EA_YARA_RULES)

    def _is_ea_process(self, name):
        """
        Determine whether a process name matches known EA App executables.
        """
        return name.lower() in self.EA_PROCESS_NAMES

    # -------------------------------------------------------------

    def _b64pad(self, s):
        """
        Pad Base64URL strings to a valid length for decoding.
        """
        return s + "=" * (-len(s) % 4)

    def _decode_jwt(self, token):
        """
        Decode a JWT without verifying the signature.

        This is safe for forensic analysis and allows extraction
        of claims stored in memory.
        """
        try:
            header_b64, payload_b64, _ = token.split(".")
            return {
                "header": json.loads(
                    base64.urlsafe_b64decode(self._b64pad(header_b64))
                ),
                "payload": json.loads(
                    base64.urlsafe_b64decode(self._b64pad(payload_b64))
                ),
            }
        except Exception:
            return None

    # -------------------------------------------------------------

    def _carve_json_objects(self, data):
        """
        Extract JSON objects from a raw memory buffer.

        Uses a simple brace-based heuristic suitable for
        Electron / Node.js memory artefacts.
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
        Scan readable VAD regions belonging to a process.

        Memory is scanned in fixed-size chunks to:
        - Avoid invalid address exceptions
        - Reduce memory overhead
        - Improve stability on fragmented VADs
        """
        process_layer_name = proc.add_process_layer()
        layer = context.layers[process_layer_name]

        for vad in vadinfo.VadInfo.list_vads(proc):
            try:
                # Decode VAD protection flags using Volatility helpers
                protection = vad.get_protection(
                    vadinfo.PROTECT_VALUES,
                    vadinfo.WINNT_PROTECTIONS
                )
            except Exception:
                continue

            # Only scan readable memory regions
            if not protection or "READ" not in protection:
                continue

            vad_start = vad.get_start()
            vad_end = vad.get_end()

            for offset in range(vad_start, vad_end, self.VAD_CHUNK_SIZE):
                try:
                    chunk = layer.read(
                        offset,
                        self.VAD_CHUNK_SIZE,
                        pad=True
                    )
                except exceptions.InvalidAddressException:
                    continue

                # Only return chunks that trigger the YARA rules
                if rules.match(data=chunk):
                    yield chunk

    # -------------------------------------------------------------

    def _generator(self):
        """
        Core generator used by the TreeGrid renderer.

        Iterates over EA App processes, scans memory,
        extracts artefacts, and yields structured results.
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

                for obj in self._carve_json_objects(window):
                    # Structured output record
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

                    # JWT detection and decoding
                    for val in obj.values():
                        if isinstance(val, str) and val.startswith("eyJ"):
                            decoded = self._decode_jwt(val)
                            if decoded:
                                record["jwt"] = decoded

                    # Account metadata
                    for k in self.ACCOUNT_KEYS:
                        if k in obj:
                            record["account"][k] = obj[k]

                    # Device identifiers
                    for k in self.DEVICE_KEYS:
                        if k in obj:
                            record["device"][k] = obj[k]

                    # Game / entitlement information
                    for k in self.GAME_KEYS:
                        if k in obj:
                            record["game"][k] = obj[k]

                    # EA network endpoints
                    for v in obj.values():
                        if isinstance(v, str) and "ea.com" in v:
                            record["network"].setdefault(
                                "endpoints", []
                            ).append(v)

                    # Only emit records that contain useful data
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
        Entry point for the Volatility renderer.
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
