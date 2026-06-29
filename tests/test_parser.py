from cachelint.parser import parse_dockerfile


def test_line_continuation_is_joined():
    df = parse_dockerfile("RUN apt-get update \\\n    && apt-get install -y curl\n")
    run = df.all_instructions[0]
    assert run.keyword == "RUN"
    assert "apt-get update" in run.args and "install -y curl" in run.args
    assert run.start_line == 1
    assert run.end_line == 2


def test_comments_and_blank_lines_are_skipped():
    src = "# a comment\n\nFROM alpine\n# another\nRUN echo hi\n"
    df = parse_dockerfile(src)
    kinds = [i.keyword for i in df.all_instructions]
    assert kinds == ["FROM", "RUN"]


def test_copy_shell_form_with_flags():
    df = parse_dockerfile("FROM x\nCOPY --chown=node:node --from=build src/ /app/\n")
    copy = df.stages[0].instructions[0]
    assert copy.keyword == "COPY"
    assert copy.sources == ["src/"]
    assert copy.dest == "/app/"
    assert copy.flags.get("from") == "build"
    assert copy.flags.get("chown") == "node:node"


def test_copy_json_form():
    df = parse_dockerfile('FROM x\nCOPY ["package.json", "./"]\n')
    copy = df.stages[0].instructions[0]
    assert copy.sources == ["package.json"]
    assert copy.dest == "./"


def test_run_mount_flag_is_captured():
    df = parse_dockerfile(
        "FROM x\nRUN --mount=type=cache,target=/root/.npm npm ci\n"
    )
    run = df.stages[0].instructions[0]
    assert run.keyword == "RUN"
    assert any("type=cache" in m for m in run.flags.get("mount", []))


def test_multi_stage_named():
    src = "FROM golang AS build\nRUN go build\nFROM alpine\nCOPY --from=build /app /app\n"
    df = parse_dockerfile(src)
    assert len(df.stages) == 2
    assert df.stages[0].name == "build"
    assert df.stages[0].base == "golang"
    assert df.stages[1].name is None


def test_escape_directive_backtick():
    src = "# escape=`\nFROM x\nRUN echo a `\n  b\n"
    df = parse_dockerfile(src)
    assert df.escape == "`"
    run = df.stages[0].instructions[0]
    assert "a" in run.args and "b" in run.args


def test_syntax_directive():
    df = parse_dockerfile("# syntax=docker/dockerfile:1\nFROM x\n")
    assert df.syntax == "docker/dockerfile:1"


def test_heredoc_is_consumed():
    src = "FROM x\nRUN <<EOF\napt-get update\napt-get install -y curl\nEOF\nCOPY a b\n"
    df = parse_dockerfile(src)
    kinds = [i.keyword for i in df.stages[0].instructions]
    assert kinds == ["RUN", "COPY"]
    run = df.stages[0].instructions[0]
    assert "install -y curl" in run.args


def test_inline_ignore_directive():
    df = parse_dockerfile("FROM x\nRUN npm ci # cachelint:ignore=CL001\n")
    run = df.stages[0].instructions[0]
    assert "CL001" in run.suppressed_rules


def test_pre_from_args():
    df = parse_dockerfile("ARG VERSION=1\nFROM alpine:${VERSION}\nRUN echo hi\n")
    assert df.pre_from and df.pre_from[0].keyword == "ARG"
    assert len(df.stages) == 1
