{
  description = "TLC model-checking suite for the tapreorg anchoring watcher";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      eachSystem = f: nixpkgs.lib.genAttrs systems (system:
        f nixpkgs.legacyPackages.${system});

      # Verdict-aware runner: every configuration carries its
      # expectation — suites must HOLD, probes and counterexample
      # configurations must be VIOLATED — so a green run means the
      # entire battery behaved, reachability probes included. The
      # explicit -Xmx keeps the largest instances from being
      # OOM-killed under default JVM sizing.
      runner = pkgs: pkgs.writeShellScriptBin "watcher-tlc" ''
        set -u

        JAVA="${pkgs.jdk8}/bin/java"
        JAR="${pkgs.tlaplus}/share/java/tla2tools.jar"
        SRC="${self}"
        FAIL=0
        tier="''${1:-quick}"

        run_tlc() {
          meta=$(mktemp -d)
          "$JAVA" -Xmx4g -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
            -deadlock -workers auto -checkpoint 0 -metadir "$meta" \
            -config "$SRC/$1.cfg" "$SRC/$2"
          rm -rf "$meta"
        }

        check() {
          exp=$1; cfg=$2; mod=$3
          t0=$(date +%s)
          out=$(run_tlc "$cfg" "$mod" 2>&1)
          dt=$(( $(date +%s) - t0 ))
          if [ "$exp" = hold ] && printf '%s' "$out" \
              | grep -q "No error has been found"; then
            echo "PASS  $cfg: holds (''${dt}s)"
          elif [ "$exp" = violated ] && printf '%s' "$out" \
              | grep -q "is violated"; then
            echo "PASS  $cfg: violated as expected (''${dt}s)"
          else
            echo "FAIL  $cfg: expected to be $exp (''${dt}s)"
            printf '%s\n' "$out" | tail -25
            FAIL=1
          fi
        }

        probes() {
          check violated MC_boundary MC
          check violated MC_tear MC
          check violated MC_reach_NeverBuried MC
          check violated MC_reach_NeverAbandoned MC
          check violated MC_reach_NeverConflicted MC
          check violated MC_reach_NeverStaleOnFlag MC
          check violated MC_reach_NeverDeliveredTerminal MC
          check violated MC_reach_NeverRegression MC
          check violated MC_reach_NeverTwoForeign MC
          check violated MC_reach_NeverSplitAbandonment MC
          check violated MC2_boundary MC2
          check violated MC2_reach_NeverFcStaged MC2
          check violated MC2_reach_NeverFcCertified MC2
          check violated MC2_reach_NeverFcOffChain MC2
          check violated MC2_reach_NeverChildForeclosed MC2
          check violated MC2_reach_NeverChildBuried MC2
          check violated MC2_reach_NeverReleaseCPerformed MC2
          check violated MC2_reach_NeverCompensatePPerformed MC2
          check violated MC3_reach_NeverMixedOutcome MC3
          check violated MC3_reach_NeverDoubleRelease MC3
          check violated MC3_reach_NeverMixedSettlement MC3
        }

        fast_holds() {
          check hold MC3_dupreg MC3
          check hold MC_live MC
          check hold MC2_foreign MC2
          check hold MC2_discipline MC2
        }

        safety() {
          check hold MC_safety MC
          check hold MC_split MC
          check hold MC_discipline MC
          check hold MC2_repl MC2
          check hold MC2_foreign MC2
          check hold MC2_full MC2
          check hold MC2_discipline MC2
          check hold MC3_dupreg MC3
          check hold MC3_dualchild MC3
        }

        liveness() {
          check hold MC_live MC
          check hold MC2_live_repl MC2
          check hold MC2_live_foreign MC2
        }

        case "$tier" in
          probes)   probes ;;
          quick)    probes; fast_holds ;;
          safety)   safety ;;
          liveness) liveness ;;
          all)      probes; safety; liveness ;;
          *)
            echo "usage: watcher-tlc [probes|quick|safety|liveness|all]"
            echo "  probes    all expected-violated runs (~2 min)"
            echo "  quick     probes plus the fast suites (~10 min," \
                 "the default)"
            echo "  safety    every exhaustive safety suite (~1.5 h)"
            echo "  liveness  the three liveness suites (~20 min)"
            echo "  all       everything (~2 h)"
            exit 2
            ;;
        esac

        if [ "$FAIL" = 0 ]; then
          echo "== all $tier checks behaved as expected =="
        else
          echo "== FAILURES in $tier tier =="
        fi
        exit "$FAIL"
      '';
    in {
      packages = eachSystem (pkgs: {
        default = runner pkgs;
      });

      apps = eachSystem (pkgs: {
        default = {
          type = "app";
          program = "${runner pkgs}/bin/watcher-tlc";
        };
      });

      # `nix flake check` runs the probe battery: fast, and it
      # exercises every module and the model's reachability floor.
      checks = eachSystem (pkgs: {
        probes = pkgs.runCommand "watcher-tlc-probes" { } ''
          ${runner pkgs}/bin/watcher-tlc probes | tee $out
        '';
      });

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.tlaplus (runner pkgs) ];
        };
      });
    };
}
