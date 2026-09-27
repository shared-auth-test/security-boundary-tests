{ config, lib, ... }:

let
  cfg = config.services.bmsclLifecycleAgent;
  stateRoot = "/var/lib/beamscale/lifecycle";
  managedCgroupRoot = "/sys/fs/cgroup/beamscale-workloads.slice";
  lifecycleKeyPrefix = "beamscale/runtime-lifecycle";
in
{
  options.services.bmsclLifecycleAgent = {
    enable = lib.mkEnableOption "BeamScale external host lifecycle agent";

    package = lib.mkOption {
      type = lib.types.package;
      description = "Pinned package containing the shared ORE process lifecycle agent.";
    };

    binary = lib.mkOption {
      type = lib.types.str;
      default = "ores-process-lifecycle-agent";
    };

    reconcileSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 15;
    };

    environmentName = lib.mkOption {
      type = lib.types.str;
      default = "prod";
      description = "Separator-safe deployment environment used in lifecycle lease keys.";
    };

    region = lib.mkOption {
      type = lib.types.str;
      description = "Separator-safe region/failure-domain component used in lifecycle lease keys.";
    };

    cluster = lib.mkOption {
      type = lib.types.str;
      description = "Stable BeamScale cluster/cell identity recorded in lifecycle evidence.";
    };

    node = lib.mkOption {
      type = lib.types.str;
      default = config.networking.hostName;
      description = "Stable host identity recorded in lifecycle evidence.";
    };

    leaseProvider = lib.mkOption {
      type = lib.types.enum [ "cloudflare_durable_object" "fiducia" ];
      default = "cloudflare_durable_object";
      description = "Provider-neutral distributed lease authority.";
    };

    leaseEndpoint = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Absolute credential-free HTTPS endpoint for the lifecycle lease authority.";
    };

    credentialName = lib.mkOption {
      type = lib.types.str;
      default = "ores-locks-api-token";
      description = "systemd credential name containing the scoped lease-authority token.";
    };

    credentialFiles = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      description = "Credential name to host path; secret values stay outside the Nix store and environment.";
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      description = "Non-secret lifecycle-agent environment only.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
            cfg.environmentName != null;
        message = "BeamScale lifecycle environmentName must be a separator-safe lease-key component";
      }
      {
        assertion =
          builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
            cfg.region != null;
        message = "BeamScale lifecycle region must be a separator-safe lease-key component";
      }
      {
        assertion =
          builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
            cfg.cluster != null;
        message = "BeamScale lifecycle cluster must be a separator-safe identity";
      }
      {
        assertion =
          builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
            cfg.node != null;
        message = "BeamScale lifecycle node must be a separator-safe identity";
      }
      {
        assertion =
          builtins.match
            "^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[^[:space:]]*)?$"
            cfg.leaseEndpoint != null;
        message = "BeamScale lifecycle lease endpoint must be an absolute credential-free https URL";
      }
      {
        assertion = builtins.hasAttr cfg.credentialName cfg.credentialFiles;
        message = "BeamScale lifecycle credentialName must reference an entry in credentialFiles";
      }
      {
        assertion =
          builtins.match "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
            cfg.credentialName != null;
        message = "BeamScale lifecycle credentialName must be a safe systemd credential identifier";
      }
    ];

    systemd.slices."beamscale-workloads" = {
      description = "BeamScale suspendable workload processes";
      sliceConfig = {
        CPUAccounting = true;
        MemoryAccounting = true;
        TasksAccounting = true;
      };
    };

    systemd.tmpfiles.rules = [
      "d ${stateRoot} 0700 root root -"
    ];

    systemd.services.bmscl-lifecycle-agent = {
      description = "BeamScale fenced host freeze/thaw lifecycle agent";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      environment = cfg.environment // {
        ORES_PROCESS_LIFECYCLE_PRODUCT = "beamscale";
        ORES_PROCESS_LIFECYCLE_ENVIRONMENT = cfg.environmentName;
        ORES_PROCESS_LIFECYCLE_REGION = cfg.region;
        ORES_PROCESS_LIFECYCLE_CLUSTER = cfg.cluster;
        ORES_PROCESS_LIFECYCLE_NODE = cfg.node;
        ORES_PROCESS_LIFECYCLE_STATE_ROOT = stateRoot;
        ORES_PROCESS_LIFECYCLE_CGROUP_ROOT = managedCgroupRoot;
        ORES_PROCESS_LIFECYCLE_RECONCILE_SECONDS = toString cfg.reconcileSeconds;
        ORES_PROCESS_LIFECYCLE_LEASE_PROVIDER = cfg.leaseProvider;
        ORES_PROCESS_LIFECYCLE_LEASE_ENDPOINT = cfg.leaseEndpoint;
        ORES_PROCESS_LIFECYCLE_LEASE_KEY_PREFIX = lifecycleKeyPrefix;
        ORES_PROCESS_LIFECYCLE_CREDENTIAL_NAME = cfg.credentialName;
        ORES_PROCESS_LIFECYCLE_EFFECTS = "freeze_thaw";
      };

      serviceConfig = {
        # This first tranche is deliberately freeze/thaw-only. It may write
        # cgroup.freeze under exactly beamscale-workloads.slice, but it does not
        # receive checkpoint/ptrace/mount/kernel capabilities.
        User = "root";
        Group = "root";
        ExecStart = "${cfg.package}/bin/${cfg.binary}";
        Restart = "always";
        RestartSec = "2s";
        LoadCredential =
          lib.mapAttrsToList (name: path: "${name}:${path}") cfg.credentialFiles;

        NoNewPrivileges = true;
        CapabilityBoundingSet = [ ];
        AmbientCapabilities = [ ];
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = false;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        UMask = "0077";

        # The host cgroup hierarchy is read-only except for the one fixed
        # suspendable workload slice. Do not accept a configurable cgroup path.
        ReadOnlyPaths = [ "/sys/fs/cgroup" ];
        ReadWritePaths = [
          stateRoot
          managedCgroupRoot
        ];
      };
    };
  };
}
