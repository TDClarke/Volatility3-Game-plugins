# “Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement”;
"""
SteamArtifacts Volatility 3 Plugin
=================================

This Volatility 3 plugin extracts Steam-related forensic artefacts from
Windows memory images.

It targets Steam client processes (steam.exe and steamwebhelper.exe),
walks their virtual address spaces (VADs), extracts printable strings
(both ASCII and UTF-16LE), and filters them for Steam-specific indicators
such as installation paths, SteamIDs, URLs, and network artefacts.

Why UTF-16LE?
-------------
Most Windows applications store strings in UTF-16LE format. Limiting
extraction to ASCII would miss the majority of relevant artefacts.

Author: Thomas Clarke
"""

import re

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist


class SteamArtifacts(interfaces.plugins.PluginInterface):
    """
    Volatility 3 plugin to extract Steam-related artefacts from memory.

    The plugin:
    1. Locates Steam-related processes
    2. Walks each process's virtual memory regions (VADs)
    3. Extracts ASCII and UTF-16LE strings
    4. Filters results for Steam-specific content
    5. Outputs results in a TreeGrid
    """

    # Minimum Volatility framework version required
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        """
        Declare plugin requirements.

        This plugin requires access to the Windows kernel module
        to enumerate running processes.

        Returns
        -------
        list
            A list of Volatility requirements.
        """
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]

    # ------------------------------------------------------------
    # Locate Steam-related processes
    # ------------------------------------------------------------
    def _get_steam_processes(self):
        """
        Identify Steam-related processes in memory.

        Uses pslist to iterate over active processes and safely
        extracts the ImageFileName field without assuming UTF-8
        encoding.

        Yields
        ------
        interfaces.objects.ObjectInterface
            Process objects corresponding to Steam components.
        """
        kernel = self.context.modules[self.config["kernel"]]

        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=kernel.name,
        ):
            try:
                # Convert fixed-length char array safely
                name = utility.array_to_string(proc.ImageFileName)

                # Steam architecture separates functionality
                # between steam.exe and steamwebhelper.exe
                if name.lower() in ("steam.exe", "steamwebhelper.exe"):
                    yield proc

            except exceptions.InvalidAddressException:
                # Skip processes with unreadable structures
                continue

    # ------------------------------------------------------------
    # Extract strings from process memory
    # ------------------------------------------------------------
    def _extract_strings(self, proc, min_len=6):
        """
        Extract printable ASCII and UTF-16LE strings from a process.

        The function:
        - Creates a process memory layer
        - Walks all Virtual Address Descriptors (VADs)
        - Reads memory safely
        - Extracts strings using regular expressions

        Parameters
        ----------
        proc : interfaces.objects.ObjectInterface
            Target process.
        min_len : int, optional
            Minimum string length to extract.

        Yields
        ------
        str
            Extracted printable strings.
        """
        try:
            # Create a process-specific memory layer
            proc_layer_name = proc.add_process_layer()
        except exceptions.InvalidAddressException:
            return

        layer = self.context.layers[proc_layer_name]

        # Traverse all memory regions belonging to the process
        for vad in proc.get_vad_root().traverse():
            try:
                # Read the full VAD region
                data = layer.read(
                    vad.get_start(),
                    vad.get_size(),
                    pad=True,
                )
            except exceptions.InvalidAddressException:
                # Skip unreadable memory regions
                continue

            # -----------------------------
            # ASCII string extraction
            # -----------------------------
            for match in re.finditer(rb"[ -~]{%d,}" % min_len, data):
                yield match.group().decode(errors="ignore")

            # -----------------------------
            # UTF-16LE string extraction
            # -----------------------------
            # Pattern matches printable characters followed by NULL bytes
            for match in re.finditer(
                rb"(?:[\x20-\x7E]\x00){%d,}" % min_len,
                data,
            ):
                yield match.group().decode("utf-16le", errors="ignore")

    # ------------------------------------------------------------
    # Steam-specific artefact filtering
    # ------------------------------------------------------------
    def _steam_string_filter(self, s):
        """
        Determine whether a string is Steam-related.

        Applies keyword and pattern matching to identify
        installation paths, SteamIDs, URLs, and service components.

        Parameters
        ----------
        s : str
            String to evaluate.

        Returns
        -------
        bool
            True if the string matches Steam-related patterns.
        """
        steam_patterns = [
            r"steamapps",
            r"steamid",
            r"userdata",
            r"friends",
            r"chat",
            r"valve",
            r"lobby",
            r"gameid",
            r"cmserver",
            r"steamwebhelper",
            r"https?://.*steampowered\.com",
            r"cloud",
        ]

        for pat in steam_patterns:
            if re.search(pat, s, re.IGNORECASE):
                return True

        return False

    # ------------------------------------------------------------
    # TreeGrid row generator
    # ------------------------------------------------------------
    def _generator(self):
        """
        Generate rows for TreeGrid output.

        Iterates through Steam processes, extracts strings,
        applies filtering, and yields results for rendering.

        Yields
        ------
        tuple
            TreeGrid-compatible rows.
        """
        for proc in self._get_steam_processes():
            pid = proc.UniqueProcessId

            for s in self._extract_strings(proc):
                if self._steam_string_filter(s):
                    # Limit string length for display safety
                    yield (0, (pid, s[:300]))

    # ------------------------------------------------------------
    # Plugin entry point
    # ------------------------------------------------------------
    def run(self):
        """
        Execute the plugin.

        Returns
        -------
        renderers.TreeGrid
            A TreeGrid containing Steam artefacts and PIDs.
        """
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Steam Artefact", str),
            ],
            self._generator(),
        )
