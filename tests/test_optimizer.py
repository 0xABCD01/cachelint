from cachelint import optimizer
from cachelint.parser import parse_dockerfile


def _stage0(src, context_dir):
    df = parse_dockerfile(src, context_dir=str(context_dir))
    return df, df.stages[0]


def test_reorder_moves_install_and_inserts_manifest(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
    df, stage = _stage0(src, tmp_path)
    broad = stage.instructions[1]  # COPY . .
    install = stage.instructions[2]  # RUN npm ci
    body = optimizer.try_reorder(stage, broad, [install], df.context_dir)
    assert body is not None
    text = "\n".join(body)
    assert text.index("npm ci") < text.index("COPY . .")
    assert "package.json" in text  # synthesized manifest copy


def test_reorder_uses_detected_manifests(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "yarn.lock").write_text("")
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN yarn install\n"
    df, stage = _stage0(src, tmp_path)
    broad = stage.instructions[1]
    install = stage.instructions[2]
    body = optimizer.try_reorder(stage, broad, [install], df.context_dir)
    assert body is not None
    text = "\n".join(body)
    assert "yarn.lock" in text


def test_reorder_returns_none_when_manifest_not_in_context(tmp_path):
    # No package.json on disk -> cannot safely synthesize a COPY -> no auto-fix.
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
    df, stage = _stage0(src, tmp_path)
    broad = stage.instructions[1]
    install = stage.instructions[2]
    assert optimizer.try_reorder(stage, broad, [install], df.context_dir) is None


def test_reorder_returns_none_with_setup_between_copy_and_install(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    src = ("FROM python:3.11\nCOPY . .\nRUN ./scripts/build-deps.sh\n"
           "RUN pip install -r requirements.txt\n")
    df, stage = _stage0(src, tmp_path)
    broad = stage.instructions[0]
    install = stage.instructions[2]
    # A non-trivial RUN sits between the broad copy and the install -> unsafe.
    assert optimizer.try_reorder(stage, broad, [install], df.context_dir) is None


def test_reorder_returns_none_when_workdir_between(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    src = "FROM python:3.11\nCOPY . /app\nWORKDIR /app\nRUN pip install -r requirements.txt\n"
    df, stage = _stage0(src, tmp_path)
    broad = stage.instructions[0]
    install = stage.instructions[2]
    assert optimizer.try_reorder(stage, broad, [install], df.context_dir) is None


def test_reorder_system_install_no_manifest(tmp_path):
    src = "FROM ubuntu\nCOPY . .\nRUN apt-get install -y curl\n"
    df, stage = _stage0(src, tmp_path)
    broad = stage.instructions[0]
    install = stage.instructions[1]
    body = optimizer.try_reorder(stage, broad, [install], df.context_dir)
    assert body is not None
    text = "\n".join(body)
    assert text.index("apt-get install") < text.index("COPY . .")
    # no language manifest copy synthesized for apt
    assert "package.json" not in text


def test_reorder_carries_chown_flag(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    src = "FROM node:20\nWORKDIR /app\nUSER node\nCOPY --chown=node:node . .\nRUN npm ci\n"
    df, stage = _stage0(src, tmp_path)
    broad = stage.instructions[2]  # COPY --chown=node:node . .
    install = stage.instructions[3]
    body = optimizer.try_reorder(stage, broad, [install], df.context_dir)
    assert body is not None
    synthesized = [l for l in body if l.startswith("COPY") and "package.json" in l][0]
    assert "--chown=node:node" in synthesized


def test_regenerate_file_preserves_other_stages(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    src = ("FROM node:20 AS build\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
           "FROM nginx\nCOPY --from=build /app/dist /usr/share/nginx/html\n")
    df = parse_dockerfile(src, context_dir=str(tmp_path))
    stage = df.stages[0]
    broad = stage.instructions[1]
    install = stage.instructions[2]
    body = optimizer.try_reorder(stage, broad, [install], df.context_dir)
    assert body is not None
    out = optimizer.regenerate_file(df, {0: body})
    assert "FROM nginx" in out
    assert "COPY --from=build" in out
    assert out.index("npm ci") < out.index("COPY . .")
