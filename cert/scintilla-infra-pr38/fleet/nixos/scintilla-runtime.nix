{ config, lib, pkgs, ... }:

let
  cfg = config.services.scintillaRuntime;
  lifecycleKeyPrefix = "scintilla/runtime-lifecycle";
  lifecycleCheckpointRoot = "${cfg.stateRoot}/hibernation";
in
{
  options.services.scintillaRuntime = {
    enable = lib.mkEnableOption "Scintilla bare-process runtime host";
    runnerPackage = lib.mkOption {
      type = lib.types.package;
      description = "Immutable package containing the Scintilla runtime agent.";
    };
    runnerBinary = lib.mkOption {
      type = lib.types.str;
      default = "scintilla-agent";
    };
    isolationPackage = lib.mkOption {
      type = lib.types.package;
      description = "Pinned ORESoftware ores-proc-isolation-cli package.";
    };
    isolationBinary = lib.mkOption {
      type = lib.types.str;
      default = "ores-proc-isolation";
    };
    bundleRoot = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/scintilla/bundles";
    };
    stateRoot = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/scintilla";
    };
    runtimeUser = lib.mkOption {
      type = lib.types.str;
      default = "scintilla";
    };
    credentialFiles = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      description = "Credential name to host path; values must stay outside the Nix store.";
    };
    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      description = "Non-secret runtime environment only.";
    };
    lifecycle = {
      enable = lib.mkEnableOption "fenced Scintilla runtime hibernation/resume control";
      provider = lib.mkOption {
        type = lib.types.enum [ "cloudflare_durable_object" "fiducia" ];
        default = "cloudflare_durable_object";
        description = "Distributed lifecycle lease authority; provider swaps must preserve the shared Lease contract.";
      };
      leaseEndpoint = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Non-secret HTTPS endpoint for the distributed lifecycle lease authority.";
      };
      environmentName = lib.mkOption {
        type = lib.types.str;
        default = "prod";
        description = "Lifecycle environment component used beneath the product key prefix.";
      };
      credentialName = lib.mkOption {
        type = lib.types.str;
        default = "ores-locks-api-token";
        description = "systemd credential name containing the scoped lease-authority bearer/token.";
      };
      reconcileIntervalMs = lib.mkOption {
        type = lib.types.int;
        default = 5000;
      };
      warmIdleMs = lib.mkOption {
        type = lib.types.int;
        default = 10000;
      };
      hibernateAfterMs = lib.mkOption {
        type = lib.types.int;
        default = 60000;
      };
      leaseTtlMs = lib.mkOption {
        type = lib.types.int;
        default = 30000;
      };
      renewEveryMs = lib.mkOption {
        type = lib.types.int;
        default = 10000;
      };
    };
    memoryMax = lib.mkOption {
      type = lib.types.str;
      default = "80%";
    };
    cpuQuota = lib.mkOption {
      type = lib.types.str;
      default = "800%";
    };
    tasksMax = lib.mkOption {
      type = lib.types.int;
      default = 32768;
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = lib.optionals cfg.lifecycle.enable [
      {
        assertion = cfg.lifecycle.leaseEndpoint != "";
        message = "services.scintillaRuntime.lifecycle.leaseEndpoint is required when lifecycle control is enabled";
      }
      {
        assertion =
          builtins.match
            "^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[^[:space:]]*)?$"
            cfg.lifecycle.leaseEndpoint != null;
        message = "runtime lifecycle lease endpoint must be an absolute credential-free https URL";
      }
      {
        assertion = builtins.hasAttr cfg.lifecycle.credentialName cfg.credentialFiles;
        message = "runtime lifecycle credentialName must reference an entry in credentialFiles";
      }
      {
        assertion = builtins.hasAttr "SCINTILLA_REGION" cfg.environment;
        message = "SCINTILLA_REGION is required when runtime lifecycle control is enabled";
      }
      {
        assertion =
          builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
            (cfg.environment.SCINTILLA_REGION or "") != null;
        message = "SCINTILLA_REGION must be a separator-safe lifecycle key component";
      }
      {
        assertion =
          builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
            cfg.lifecycle.environmentName != null;
        message = "runtime lifecycle environmentName must be a separator-safe key component";
      }
      {
        assertion =
          builtins.match "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
            cfg.lifecycle.credentialName != null;
        message = "runtime lifecycle credentialName must be a safe systemd credential identifier";
      }
      {
        assertion =
          cfg.lifecycle.reconcileIntervalMs > 0
          && cfg.lifecycle.warmIdleMs > 0
          && cfg.lifecycle.hibernateAfterMs > cfg.lifecycle.warmIdleMs;
        message = "runtime lifecycle reconciliation/idle timings must be positive and hibernateAfterMs must exceed warmIdleMs";
      }
      {
        assertion =
          cfg.lifecycle.leaseTtlMs > 0
          && cfg.lifecycle.renewEveryMs > 0
          && (cfg.lifecycle.renewEveryMs * 2) <= cfg.lifecycle.leaseTtlMs;
        message = "runtime lifecycle renewal cadence must be no greater than half the lease TTL";
      }
    ];

    users.groups.scintilla = {};
    users.users.${cfg.runtimeUser} = {
      isSystemUser = true;
      group = "scintilla";
      home = cfg.stateRoot;
      createHome = true;
    };

    environment.systemPackages = [
      cfg.runnerPackage
      cfg.isolationPackage
      pkgs.bubblewrap
      pkgs.slirp4netns
      pkgs.iproute2
      pkgs.nftables
    ];

    systemd.tmpfiles.rules = [
      "d ${cfg.stateRoot} 0750 ${cfg.runtimeUser} scintilla -"
      "d ${cfg.bundleRoot} 0750 ${cfg.runtimeUser} scintilla -"
    ] ++ lib.optionals cfg.lifecycle.enable [
      "d ${lifecycleCheckpointRoot} 0700 ${cfg.runtimeUser} scintilla -"
    ];

    systemd.services.scintilla-runtime = {
      description = "Scintilla bare-process runtime agent";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      environment = cfg.environment // {
        SCINTILLA_EXECUTOR = "process";
        SCINTILLA_BUNDLE_ROOT = cfg.bundleRoot;
        SCINTILLA_ISOLATION_BINARY = "${cfg.isolationPackage}/bin/${cfg.isolationBinary}";
      } // lib.optionalAttrs cfg.lifecycle.enable {
        SCINTILLA_LIFECYCLE_ENABLED = "1";
        SCINTILLA_LIFECYCLE_PROVIDER = cfg.lifecycle.provider;
        SCINTILLA_LIFECYCLE_ENDPOINT = cfg.lifecycle.leaseEndpoint;
        SCINTILLA_LIFECYCLE_KEY_PREFIX = lifecycleKeyPrefix;
        SCINTILLA_LIFECYCLE_ENVIRONMENT = cfg.lifecycle.environmentName;
        SCINTILLA_LIFECYCLE_CREDENTIAL_NAME = cfg.lifecycle.credentialName;
        SCINTILLA_LIFECYCLE_CHECKPOINT_ROOT = lifecycleCheckpointRoot;
        SCINTILLA_LIFECYCLE_RECONCILE_INTERVAL_MS = toString cfg.lifecycle.reconcileIntervalMs;
        SCINTILLA_LIFECYCLE_WARM_IDLE_MS = toString cfg.lifecycle.warmIdleMs;
        SCINTILLA_LIFECYCLE_HIBERNATE_AFTER_MS = toString cfg.lifecycle.hibernateAfterMs;
        SCINTILLA_LIFECYCLE_LEASE_TTL_MS = toString cfg.lifecycle.leaseTtlMs;
        SCINTILLA_LIFECYCLE_RENEW_EVERY_MS = toString cfg.lifecycle.renewEveryMs;
      };

      serviceConfig = {
        User = cfg.runtimeUser;
        Group = "scintilla";
        ExecStart = "${cfg.runnerPackage}/bin/${cfg.runnerBinary}";
        Restart = "on-failure";
        RestartSec = "2s";
        LoadCredential = lib.mapAttrsToList (name: path: "${name}:${path}") cfg.credentialFiles;

        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        ProcSubset = "pid";
        RestrictSUIDSGID = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RemoveIPC = true;
        UMask = "0077";

        ReadWritePaths = [ cfg.stateRoot ];
        MemoryMax = cfg.memoryMax;
        CPUQuota = cfg.cpuQuota;
        TasksMax = cfg.tasksMax;
        LimitNOFILE = 65536;
      };
    };
  };
}
