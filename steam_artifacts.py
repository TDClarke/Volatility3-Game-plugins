#“Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement”;

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
import re


class SteamArtifacts(interfaces.plugins.PluginInterface):
    """Extract forensic artefacts from the Steam client (steam.exe)"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            )
        ]

    # ------------------------------------------------------------
    # Locate steam.exe
    # ------------------------------------------------------------
    def _get_steam_processes(self):
        kernel = self.context.modules[self.config["kernel"]]

        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=kernel.name
        ):
            try:
                name = proc.ImageFileName.cast("string", max_length=15)
                if name.lower() == "steam.exe":
                    yield proc
            except exceptions.InvalidAddressException:
                continue

    # ------------------------------------------------------------
    # Extract printable strings (symbol-safe)
    # ------------------------------------------------------------
    def _extract_strings(self, proc, min_len=6):
        try:
            proc_layer_name = proc.add_process_layer()
        except exceptions.InvalidAddressException:
            return

        layer = self.context.layers[proc_layer_name]


        for vad in proc.get_vad_root().traverse():
            try:
                data = layer.read(
                    vad.get_start(),
                    vad.get_size(),
                    pad=True
                )
            except exceptions.InvalidAddressException:
                continue

            for match in re.finditer(rb"[ -~]{%d,}" % min_len, data):
                yield match.group().decode(errors="ignore")

    # ------------------------------------------------------------
    # Steam-specific filter
    # ------------------------------------------------------------
    def _steam_string_filter(self, s):
        steam_patterns = [
            r"steamapps",
            r"SteamID",
            r"friends",
            r"chat",
            r"userdata",
            r"Valve",
            r"Lobby",
            r"GameID",
            r"CMServer",
            r"https?://.*steampowered\.com",
            r"steamwebhelper",
            r"cloud",
        ]

        for pat in steam_patterns:
            if re.search(pat, s, re.IGNORECASE):
                return True
        return False

    # ------------------------------------------------------------
    # TreeGrid generator (REQUIRED)
    # ------------------------------------------------------------
    def _generator(self):
        for proc in self._get_steam_processes():
            pid = proc.UniqueProcessId

            for s in self._extract_strings(proc):
                if self._steam_string_filter(s):
                    yield (0, (pid, s[:300]))

    # ------------------------------------------------------------
    # Plugin entry point
    # ------------------------------------------------------------
    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Steam Artefact", str),
            ],
            self._generator()
        )
