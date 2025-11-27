{
  description = "taproot-assets";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        package = "taproot-assets";
        tag = "v0.7.0";

        # source info
        org = "lightninglabs";
        repo = package;
        tap_src = pkgs.fetchFromGitHub {
          owner = org;
          repo = repo;
          rev = tag;
          hash = "sha256-z4lNeVmy0AEDM8ivdfXfXqi/V1LIDHV2KtS5/19+Jlk=";
        };

        # ldflags
        ldflags_base = [ "-X" "github.com/${org}/${repo}.Commit=${tag}" ];
        ldflags_dev = ldflags_base;
        ldflags_release = [ "-s" "-w" ] ++ ldflags_base;

        # tags
        tags_base = [ "monitoring" ];
        tags_dev = [ "dev" ] ++ tags_base;
        tags_release = tags_base;

        # gcflags
        gcflags_dev = [ "all=-N -l" ];

        # tapd builder
        build_tap = {
              goos ? null
            , goarch ? null
            , goarm ? null
            , tags ? tags_base
            , ldflags ? ldflags_base
            , gcflags ? [ ]
            }: pkgs.buildGoModule {
          pname = package;
          version = tag;
          src = tap_src;
          vendorHash = "sha256-p75eZoM6tSayrxcKTCoXR8Jlc3y2UyzfPCtRJmDy9ew=";
          subPackages = [ "cmd/tapd" "cmd/tapcli" ];

          inherit tags ldflags gcflags;

          preBuild = with pkgs; ''
            export CGO_ENABLED="0"
            export GOAMD64="v1"
            ${lib.optionalString (goos != null) "export GOOS=${goos}"}
            ${lib.optionalString (goarch != null) "export GOARCH=${goarch}"}
            ${lib.optionalString (goarm != null) "export GOARM=${goarm}"}
          '';

          doCheck = false;
        };

        # release builder
        build_tap_release = { goos, goarch, goarm ? null }: build_tap {
          inherit goos goarch goarm;
          tags = tags_release;
          ldflags = ldflags_release;
        };

      in
        {
          packages.tap = build_tap {
            tags = tags_base;
            ldflags = ldflags_base;
          };

          packages.tap-dev = build_tap {
            tags = tags_dev;
            ldflags = ldflags_dev;
            gcflags = gcflags_dev;
          };

          packages.tap-darwin-amd64 = build_tap_release {
            goos = "darwin";
            goarch = "amd64";
          };

          packages.tap-darwin-arm64 = build_tap_release {
            goos = "darwin";
            goarch = "arm64";
          };

          packages.tap-linux-amd64 = build_tap_release {
            goos = "linux";
            goarch = "amd64";
          };

          packages.tap-linux-arm64 = build_tap_release {
            goos = "linux";
            goarch = "arm64";
          };

          packages.tap-linux-386 = build_tap_release {
            goos = "linux";
            goarch = "386";
          };

          packages.tap-linux-armv6 = build_tap_release {
            goos = "linux";
            goarch = "arm";
            goarm = "6";
          };

          packages.tap-linux-armv7 = build_tap_release {
            goos = "linux";
            goarch = "arm";
            goarm = "7";
          };

          packages.tap-windows-amd64 = build_tap_release {
            goos = "windows";
            goarch = "amd64";
          };

          packages.release =
            let
              inherit (self.packages.${system})
                tap tap-darwin-amd64 tap-darwin-arm64
                tap-linux-386 tap-linux-amd64 tap-linux-arm64
                tap-linux-armv6 tap-linux-armv7
                tap-windows-amd64;
            in pkgs.runCommand "taproot-assets-${tag}"
              { nativeBuildInputs = with pkgs; [ coreutils gnutar gzip zip ]; }
              ''
                set -eu
                mkdir -p $out

                # reproducible tar+gzip helper
                tar_gz() {
                  output="$1"
                  dir="$2"
                  path="$3"

                  tar --sort=name --mtime='@0' --owner=0 --group=0 \
                    --numeric-owner --mode=u+rw,go+r-w,a+X -cf - \
                    -C "$dir" "$path" | gzip -9n > "$output"
                }

                # create source, vendor archives
                tar_gz $out/vendor.tar.gz ${tap.goModules} .
                tar_gz $out/taproot-assets-source-${tag}.tar.gz ${tap_src} .

                # create per-platform archives
                bundle() {
                  platform="$1"
                  src="$2"
                  srcdir="''${3:-$1}"

                  ext=""
                  if [[ "$platform" == windows-* ]]; then
                    ext=".exe"
                  fi

                  staging="taproot-assets-$platform-${tag}"
                  mkdir -p "$staging"

                  if [ -d "$src/bin/$srcdir" ]; then
                    cp -v "$src"/bin/"$srcdir"/tapd"$ext"   "$staging"/
                    cp -v "$src"/bin/"$srcdir"/tapcli"$ext" "$staging"/
                  else
                    cp -v "$src"/bin/tapd"$ext"   "$staging"/
                    cp -v "$src"/bin/tapcli"$ext" "$staging"/
                  fi

                  if [[ "$platform" == windows-* ]]; then
                    zip -X -r "$out/$staging.zip" "$staging"
                  else
                    tar_gz "$out/$staging.tar.gz" . "$staging"
                  fi

                  rm -rf "$staging"
                }

                bundle darwin-amd64 ${tap-darwin-amd64} darwin_amd64
                bundle darwin-arm64 ${tap-darwin-arm64} darwin_arm64
                bundle linux-386 ${tap-linux-386} linux_386
                bundle linux-amd64 ${tap-linux-amd64} linux_amd64
                bundle linux-arm64 ${tap-linux-arm64} linux_arm64
                bundle linux-armv6 ${tap-linux-armv6} linux_arm
                bundle linux-armv7 ${tap-linux-armv7} linux_arm
                bundle windows-amd64 ${tap-windows-amd64} windows_amd64

                # create checksummed manifest
                cd $out
                sha256sum *.tar.gz *.zip 2>/dev/null | \
                  LC_ALL=C sort -k2 > manifest-${tag}.txt
              '';

          packages.default = self.packages.${system}.tap-dev;

          devShells.default =
            let tapd = self.packages.${system}.tap-dev;
            in  pkgs.mkShell {
              buildInputs = with pkgs; [
                # compilers
                go

                # release bundle utilities
                coreutils gnutar gzip zip

                # taproot-assets
                tapd
              ];

              shellHook = ''
                PS1="[${package}] \w$ "
                echo "entering ${system} shell, using"
                echo "go:   $(${pkgs.go}/bin/go version)"
                echo "tapd: $(${tapd}/bin/tapd --version)"
              '';
            };
        });
}

