# “Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement”;
"""
SteamArtifacts Volatility 3 Plugin

Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement.

This plugin extracts forensic artefacts from the Steam client (steam.exe)
by scanning the process virtual address space for printable strings and
filtering them for Steam-related indicators such as SteamIDs, URLs,
installation paths, and network artefacts.

Author: Volatility Foundation Contributor
"""

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
import re


class SteamArtifacts(interfaces.plugins.PluginInterface):
    """
    Volatility 3 plugin to extract Steam-related artefacts from memory.

    The plugin locates running instances of steam.exe, walks their
    virtual address descriptors (VADs), extracts printable strings,
    and filters them for Steam-specific keywords and patterns.
    """

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        """
        Define the plugin requirements.

        Returns
        -------
        list
            A list of Volatility requirements needed to run this plugin,
            including a Windows kernel module.
        """
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
        """
        Locate steam.exe processes in memory.

        Iterates through the active process list and yields processes
        whose image name matches 'steam.exe'.

        Yields
        ------
        interfaces.objects.ObjectInterface
            A process object representing a running Steam process.
        """
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
        """
        Extract printable ASCII strings from a process memory space.

        This method creates a process layer, walks all VAD regions,
        reads their contents, and extracts printable strings using
        a regular expression.

        Parameters
        ----------
        proc : interfaces.objects.ObjectInterface
            The process object to extract strings from.
        min_len : int, optional
            Minimum length of strings to extract (default is 6).

        Yields
        ------
        str
            A decoded printable string found in process memory.
        """
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
        """
        Determine whether a string is Steam-related.

        Applies a set of Steam-specific keywords and patterns to
        identify artefacts such as paths, IDs, network endpoints,
        and client components.

        Parameters
        ----------
        s : str
            The string to evaluate.

        Returns
        -------
        bool
            True if the string matches a Steam-related pattern,
            False otherwise.
        """
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
        """
        Generate rows for Volatility TreeGrid output.

        Iterates through Steam processes, extracts strings,
        applies Steam-specific filtering, and yields results
        for rendering.

        Yields
        ------
        tuple
            A TreeGrid row containing the PID and a Steam artefact string.
        """
        for proc in self._get_steam_processes():
            pid = proc.UniqueProcessId

            for s in self._extract_strings(proc):
                if self._steam_string_filter(s):
                    yield (0, (pid, s[:300]))

    # ------------------------------------------------------------
    # Plugin entry point
    # ------------------------------------------------------------
    def run(self):
        """
        Execute the plugin.

        This is the main entry point called by Volatility.
        It returns a TreeGrid object containing extracted
        Steam artefacts.

        Returns
        -------
        renderers.TreeGrid
            A TreeGrid with PID and Steam artefact strings.
        """
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Steam Artefact", str),
            ],
            self._generator()
        )



