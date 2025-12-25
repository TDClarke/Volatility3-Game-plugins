#“Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement”;

import json
import yara
import re
import base64

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo


class EAAppArtifacts(interfaces.plugins.PluginInterface):
    """Extract EA App OAuth, identity, device, game, and network artifacts"""

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
            // JWT regex corrected - all quantifiers greedy now
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
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]

    # -------------------------------------------------------------

    def _compile_rules(self):
        return yara.compile(source=self.EA_YARA_RULES)

    def _is_ea_process(self, name):
        return name.lower() in self.EA_PROCESS_NAMES

    # -------------------------------------------------------------

    def _decode_jwt(self, token):
        try:
            header_b64, payload_b64, _ = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
            return {"header": header, "payload": payload}
        except Exception:
            return None

    # -------------------------------------------------------------

    def _carve_json_objects(self, data):
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

            for match in rules.match(data=data):
                yield data

    # -------------------------------------------------------------

    def _generator(self):
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

                    # OAuth
                    if "access_token" in obj:
                        record["oauth"]["access_token"] = obj.get("access_token")
                        record["oauth"]["expires_in"] = obj.get("expires_in")

                    if "refresh_token" in obj:
                        record["oauth"]["refresh_token"] = obj.get("refresh_token")

                    # JWT
                    for val in obj.values():
                        if isinstance(val, str) and val.startswith("eyJ"):
                            decoded = self._decode_jwt(val)
                            if decoded:
                                record["jwt"] = decoded

                    # Account
                    for k in self.ACCOUNT_KEYS:
                        if k in obj:
                            record["account"][k] = obj[k]

                    # Device
                    for k in self.DEVICE_KEYS:
                        if k in obj:
                            record["device"][k] = obj[k]

                    # Game
                    for k in self.GAME_KEYS:
                        if k in obj:
                            record["game"][k] = obj[k]

                    # Network
                    for k in obj:
                        if isinstance(obj[k], str):
                            if "ea.com" in obj[k]:
                                record["network"].setdefault("endpoints", []).append(obj[k])

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
