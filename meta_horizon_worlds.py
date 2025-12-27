#“Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement”;
"""
MetaHorizonWorlds Volatility 3 Plugin

Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement.

This plugin scans memory of Meta Horizon Worlds–related processes on Windows systems
to extract potential forensic artefacts, including:

- OAuth Bearer tokens
- In-memory chat or message fragments

The plugin enumerates process virtual address descriptors (VADs) and performs
regex-based searches on readable memory regions associated with Horizon processes.
"""

import re

from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import TreeGrid
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo


class MetaHorizonWorlds(interfaces.plugins.PluginInterface):
    """
    Volatility 3 plugin for extracting Meta Horizon Worlds artefacts from memory.

    This plugin identifies processes whose image name contains the string
    "horizon" and scans their VAD-backed memory regions for:

    - Bearer authentication tokens
    - Chat or message-like text fragments

    Results are presented in a TreeGrid with process metadata and recovered data.
    """

    # Minimum Volatility 3 framework version required
    _required_framework_version = (2, 7, 0)

    @classmethod
    def get_requirements(cls):
        """
        Define the plugin's configuration requirements.

        Returns
        -------
        list
            A list of Volatility requirement objects. This plugin requires
            a Windows kernel module for Intel 64-bit architectures.
        """
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel64"],
            )
        ]

    #: Regex pattern for detecting OAuth-style Bearer tokens in memory
    TOKEN_REGEX = re.compile(rb"Bearer\s+[A-Za-z0-9\-._~\+/=]+")

    #: Regex pattern for detecting chat or message-like strings in memory
    CHAT_REGEX = re.compile(rb"(chat|say|message)[^\x00]{5,200}", re.I)

    def _generator(self):
        """
        Memory scanning generator.

        Iterates over Horizon-related processes, enumerates their VADs, and
        searches memory contents for authentication tokens and chat artefacts.

        Yields
        ------
        tuple
            A tuple compatible with TreeGrid rows containing:
            - PID
            - Process name
            - Artefact type (TOKEN or CHAT)
            - VAD start address
            - Extracted data string
        """
        kernel = self.config["kernel"]

        # Iterate through all active processes
        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=kernel,
        ):
            name = utility.array_to_string(proc.ImageFileName)

            # Only target Horizon-related processes
            if "horizon" not in name.lower():
                continue

            try:
                # Create a process memory layer
                layer_name = proc.add_process_layer()
                layer = self.context.layers[layer_name]
            except exceptions.InvalidAddressException:
                # Skip processes with invalid memory mappings
                continue

            # Enumerate Virtual Address Descriptors (VADs)
            for vad in vadinfo.VadInfo.list_vads(proc):
                try:
                    start = vad.get_start()

                    # Limit reads to 5MB per VAD to avoid performance issues
                    size = min(vad.get_size(), 5 * 1024 * 1024)

                    data = layer.read(start, size, pad=True)
                except exceptions.InvalidAddressException:
                    continue

                # Search for Bearer tokens
                for match in self.TOKEN_REGEX.finditer(data):
                    yield (
                        0,
                        (
                            proc.UniqueProcessId,
                            name,
                            "TOKEN",
                            hex(start),
                            match.group().decode(errors="ignore"),
                        ),
                    )

                # Search for chat/message artefacts
                for match in self.CHAT_REGEX.finditer(data):
                    yield (
                        0,
                        (
                            proc.UniqueProcessId,
                            name,
                            "CHAT",
                            hex(start),
                            match.group().decode(errors="ignore"),
                        ),
                    )

    def run(self):
        """
        Execute the plugin.

        Returns
        -------
        TreeGrid
            A TreeGrid object displaying recovered artefacts, including:
            PID, process name, artefact type, VAD address, and extracted data.
        """
        return TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Type", str),
                ("VAD", str),
                ("Data", str),
            ],
            self._generator(),
        )
