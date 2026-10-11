{
  description = "noisetun – WireGuard userspace implementation in C";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "noisetun";
          version = "0.1.0";
          src = ./.;

          nativeBuildInputs = [ pkgs.cmake pkgs.pkg-config ];
          buildInputs = [ pkgs.libsodium pkgs.openssl ];

          cmakeFlags = [
            "-DWG_BUILD_TESTS=ON"
            "-DWG_BUILD_BENCH=OFF"
          ];

          doCheck = true;
          checkPhase = ''
            ctest --output-on-failure --timeout 120
          '';
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          packages = with pkgs; [
            clang-tools      # clangd, clang-format
            bear             # generates compile_commands.json
            wireguard-tools  # wg command (for integration tests)
            wireguard-go     # wireguard-go (for interop tests)
            iperf3           # throughput benchmarks
            tcpdump          # packet capture for debugging
            wireshark-cli    # tshark CLI packet analyzer
          ];
          shellHook = ''
            # Allow -march=native for performance benchmarks
            export NIX_ENFORCE_NO_NATIVE=
          '';
        };

        devShells.perf = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          packages = with pkgs; [
            wireguard-tools
            wireguard-go
            iperf3
          ];
          shellHook = ''
            export NIX_ENFORCE_NO_NATIVE=
            echo "Performance shell: OpenSSL + native enabled"
            echo "Build with: cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS='-march=native' -DWG_USE_OPENSSL=ON"
          '';
        };

        devShells.mingw = pkgs.mkShell {
          packages = with pkgs; [
            pkgsCross.mingwW64.stdenv.cc
            cmake
            pkg-config
          ];
          shellHook = ''
            export TOOLCHAIN_PREFIX=x86_64-w64-mingw32
          '';
        };
      }
    );
}
