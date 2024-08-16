{ pkgs }: {
  deps = [
    pkgs.jadx
    pkgs.unzip
    pkgs.python310
    pkgs.python310Packages.pip
    pkgs.openjdk
    pkgs.apktool
  ];
}
