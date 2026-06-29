from cachelint.model import (
    Severity,
    classify_copy,
    detect_dependency_install,
    manifest_ecosystems,
)


def test_severity_ordering_and_parse():
    assert Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.NONE
    assert Severity.parse("medium") is Severity.MEDIUM
    assert str(Severity.HIGH) == "high"


def test_classify_copy_broad():
    assert classify_copy(["."]) == "broad"
    assert classify_copy(["src"]) == "broad"
    assert classify_copy(["app/"]) == "broad"
    assert classify_copy(["./"]) == "broad"


def test_classify_copy_manifest():
    assert classify_copy(["package.json"]) == "manifest"
    assert classify_copy(["package.json", "package-lock.json"]) == "manifest"
    assert classify_copy(["go.mod", "go.sum"]) == "manifest"
    assert classify_copy(["requirements.txt"]) == "manifest"


def test_classify_copy_narrow():
    assert classify_copy(["app.py"]) == "narrow"
    assert classify_copy(["server.js", "config.yaml"]) == "narrow"


def test_detect_dependency_install_positive():
    assert detect_dependency_install("npm ci")[0] == "node"
    assert detect_dependency_install("npm install")[0] == "node"
    assert detect_dependency_install("pip install -r requirements.txt")[0] == "python"
    assert detect_dependency_install("go mod download")[0] == "go"
    assert detect_dependency_install("apt-get install -y curl")[0] == "apt"
    assert detect_dependency_install("poetry install --no-root")[0] == "python"
    assert detect_dependency_install("bundle install")[0] == "ruby"


def test_detect_dependency_install_negative():
    # build/compile steps legitimately need the full source -> not installs
    assert detect_dependency_install("npm run build") is None
    assert detect_dependency_install("go build -o app .") is None
    assert detect_dependency_install("make") is None
    assert detect_dependency_install("cargo build --release") is None
    assert detect_dependency_install("dotnet build -c Release") is None
    assert detect_dependency_install("dotnet publish -o /app") is None
    # global tool install is not a project dependency install
    assert detect_dependency_install("npm install -g typescript") is None


def test_detect_dependency_install_new_ecosystems():
    cases = {
        "dotnet restore": "dotnet",
        "nuget restore packages.config": "dotnet",
        "mix deps.get": "elixir",
        "conda env create -f environment.yml": "conda",
        "micromamba env update -f environment.yml": "conda",
        "pnpm fetch": "node",
        "flutter pub get": "dart",
        "dart pub get": "dart",
        "swift package resolve": "swift",
        "shards install": "crystal",
        "julia -e 'using Pkg; Pkg.instantiate()'": "julia",
        "lein deps": "clojure",
        "clojure -P": "clojure",
        "cpanm --installdeps .": "perl",
        "carton install": "perl",
        "stack build --only-dependencies": "haskell",
        "cabal update": "haskell",
        "sbt update": "scala",
        "Rscript -e 'renv::restore()'": "r",
        "zypper install -y curl": "zypper",
        "pacman -Syu --noconfirm git": "pacman",
        "aptitude install -y curl": "apt",
    }
    for cmd, eco in cases.items():
        got = detect_dependency_install(cmd)
        assert got is not None and got[0] == eco, (cmd, got)


def test_detect_dependency_install_new_ecosystems_negative():
    for cmd in ["swift build", "stack build", "sbt compile", "flutter build apk",
                "clojure -M:test", "lein run", "pacman -Q", "zypper search foo"]:
        assert detect_dependency_install(cmd) is None, cmd


def test_detect_dependency_install_batch3():
    cases = {
        "pdm install": "python", "pdm sync": "python",
        "pip-sync requirements.txt": "python",
        "nimble install": "nim", "gleam deps download": "gleam",
        "opam install . --deps-only --yes": "ocaml",
        "rebar3 get-deps": "erlang", "conan install .": "cpp", "vcpkg install": "cpp",
    }
    for cmd, eco in cases.items():
        got = detect_dependency_install(cmd)
        assert got is not None and got[0] == eco, (cmd, got)


def test_detect_dependency_install_batch3_negative():
    for cmd in ["pdm run test", "nimble build", "gleam run", "opam install dune",
                "rebar3 compile", "conan remote list", "vcpkg list"]:
        assert detect_dependency_install(cmd) is None, cmd


def test_batch3_manifests_classify():
    for f in ["foo.nimble", "gleam.toml", "myproj.opam", "rebar.config",
              "conanfile.txt", "vcpkg.json", "pdm.lock"]:
        assert classify_copy([f]) == "manifest", f


def test_zypper_noninteractive_install_detected():
    # -n/--non-interactive is a global flag that precedes the subcommand and is
    # the canonical Docker form.
    for cmd in ["zypper -n install foo", "zypper --non-interactive install foo",
                "zypper -n in foo", "zypper install foo"]:
        got = detect_dependency_install(cmd)
        assert got is not None and got[0] == "zypper", cmd


def test_zypper_non_install_not_detected():
    for cmd in ["zypper info foo", "zypper search foo",
                "zypper --non-interactive update", "zypper lr"]:
        assert detect_dependency_install(cmd) is None, cmd


def test_new_ecosystem_manifests_classify_as_manifest():
    for f in ["*.csproj", "MyApp.csproj", "mix.exs", "environment.yml",
              "pubspec.yaml", "Package.swift", "shard.yml", "Project.toml",
              "deps.edn", "cpanfile", "stack.yaml", "build.sbt", "renv.lock"]:
        assert classify_copy([f]) == "manifest", f


def test_manifest_ecosystems():
    assert manifest_ecosystems(["package.json"]) == {"node"}
    assert manifest_ecosystems(["go.mod", "go.sum"]) == {"go"}
    assert manifest_ecosystems(["app.py"]) == set()
