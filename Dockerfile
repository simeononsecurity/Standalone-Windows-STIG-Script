FROM mcr.microsoft.com/windows/server:ltsc2022-amd64

LABEL org.opencontainers.image.source="https://github.com/simeononsecurity/standalone-windows-stig"
LABEL org.opencontainers.image.description="Test Image for SimeonOnSecurity"
LABEL org.opencontainers.image.authors="simeononsecurity"
LABEL BaseImage="windows/server:ltsc2022-amd64"
LABEL RunnerVersion=${RUNNER_VERSION}

ARG RUNNER_VERSION
ENV container docker
ENV chocolateyUseWindowsCompression false
SHELL ["powershell.exe"]

RUN iex ((New-Object System.Net.WebClient).DownloadString('https://simeononsecurity.ch/scripts/standalonewindows.ps1'))

ENTRYPOINT ENTRYPOINT [ "powershell.exe" ]
