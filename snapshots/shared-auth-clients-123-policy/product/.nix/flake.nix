{
  description = "shared-auth client SDK development environment with ores-sops";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flags2env-src = { url = "github:oresoftware/flags-2-env"; flake = false; };
    ores-sops.url = "github:ORESoftware/ores-sops";
  };
  outputs = { self, nixpkgs, flags2env-src, ores-sops, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; config.allowUnfree = true; };
    in {
      packages = eachSystem (system:
        let pkgs = pkgsFor system;
        in {
          flags2env = pkgs.stdenv.mkDerivation {
            pname = "flags2env"; version = "git"; src = flags2env-src;
            nativeBuildInputs = [ pkgs.gnumake pkgs.stdenv.cc ];
            buildPhase = "make all";
            installPhase = ''
              mkdir -p $out/bin $out/lib
              cp build/flags2env $out/bin/
              cp build/libflags2env.* $out/lib/
            '';
            meta.mainProgram = "flags2env";
          };
          default = self.packages.${system}.flags2env;
        });
      devShells = eachSystem (system:
        let pkgs = pkgsFor system;
        in {
          default = pkgs.mkShell {
            packages = (with pkgs; [
              nodejs_22
              git
              jq
              (python3.withPackages (ps: [ ps.jsonschema ps.tomlkit ]))
              just
              sops
              age
            ])
              ++ [ self.packages.${system}.flags2env ores-sops.packages.${system}.default ];
            shellHook = ''
              echo "shared-auth client SDK development environment"
              ${ores-sops.lib.shellHook}
            '';
          };
        });
    };
}
