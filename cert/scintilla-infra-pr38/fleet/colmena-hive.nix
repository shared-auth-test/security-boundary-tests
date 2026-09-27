{ nixpkgs
, nodes
, runnerPackage
, isolationPackage
, extraModules ? []
}:

let
  lib = nixpkgs.lib;
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  mkNode = name: node: {
    deployment = {
      targetHost = node.targetHost;
      targetUser = node.targetUser or "root";
      tags = [ (node.region or "unknown") (node.cloud or "unknown") ];
    };

    imports = [ ./nixos/scintilla-runtime.nix ] ++ extraModules;
    networking.hostName = name;

    services.scintillaRuntime = {
      enable = true;
      inherit runnerPackage isolationPackage;
      environment = {
        SCINTILLA_REGION = node.region or "unknown";
        SCINTILLA_CLOUD = node.cloud or "unknown";
      } // (node.environment or {});
      credentialFiles = node.credentialFiles or {};
    };
  };
in
{
  meta = { nixpkgs = pkgs; };
} // lib.mapAttrs mkNode nodes
