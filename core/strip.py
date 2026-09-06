"""core/strip.py — Lexical source stripping for the regex engine.

Comments and string-literal contents are never executable; matching security
patterns against them produces the bulk of false positives (docstring examples,
commented-out code, test fixtures). This module produces the "code shape" of a
source file: comments and string CONTENTS are blanked with spaces (same length,
newline-preserving, delimiters kept), so line numbers and columns survive and
downstream Violations still point at the right line.

Language support (deliberately narrow):
  - python : tokenize-based (accurate; handles multi-line strings), with a
             deterministic char-scanner fallback when tokenize fails (common on
             incomplete agent fragments).
  - js     : char-scanner (// /* */ ' " ` with escape handling).
  - everything else: returned unchanged. Their rules intentionally match inside
             strings (href="javascript:", cidr_blocks=["0.0.0.0/0"], YAML values)
             and their comment handling is unchanged.

Literal-sensitive rules (rules whose patterns need string CONTENTS, e.g.
hardcoded-secret charsets like sk-.../AKIA...) must set `literal_sensitive: true`
in the rule YAML; those rules are matched against the raw line instead.
"""
from __future__ import annotations

import io
import tokenize


def _blank_region(chars: list[str], start: int, end: int) -> None:
    """Blank chars[start:end] with spaces, preserving newlines."""
    for i in range(start, min(end, len(chars))):
        if chars[i] not in "\r\n":
            chars[i] = " "


def _scan_strip(
    code: str,
    line_comments: tuple[str, ...],
    block_comments: tuple[tuple[str, str], ...],
    string_delims: str,
    triple_delims: tuple[str, ...],
) -> str:
    """Deterministic single-pass char scanner.

    Blanks comments and string-literal interiors (delimiters kept). Handles
    backslash escapes inside strings. Template-literal ${...} nesting is
    treated as plain content (rare edge; acceptable for security matching).
    """
    chars = list(code)
    n = len(code)
    i = 0
    while i < n:
        c = code[i]

        # triple-quoted strings first (python ''' """)
        matched = False
        for td in triple_delims:
            if code.startswith(td, i):
                j = code.find(td, i + len(td))
                end = (n if j < 0 else j) + len(td) if j >= 0 else n
                # keep the opening delimiter, blank interior, keep closer if present
                _blank_region(chars, i + len(td), min(end - len(td), n))
                if j < 0:
                    _blank_region(chars, min(end - len(td), n), end)
                i = end
                matched = True
                break
        if matched:
            continue

        # line comments
        hit = False
        for lc in line_comments:
            if code.startswith(lc, i):
                j = code.find("\n", i)
                j = n if j < 0 else j
                _blank_region(chars, i, j)
                i = j
                hit = True
                break
        if hit:
            continue

        # block comments
        hit = False
        for op, cl in block_comments:
            if code.startswith(op, i):
                j = code.find(cl, i + len(op))
                end = (n if j < 0 else j + len(cl))
                _blank_region(chars, i, end)
                i = end
                hit = True
                break
        if hit:
            continue

        # strings
        if c in string_delims:
            j = i + 1
            while j < n and code[j] != c:
                if code[j] == "\\":
                    j += 2
                    continue
                j += 1
            # keep both delimiters when terminated; unterminated: blank to EOL-ish
            if j < n:
                _blank_region(chars, i + 1, j)
                i = j + 1
            else:
                j2 = code.find("\n", i)
                j2 = n if j2 < 0 else j2
                _blank_region(chars, i + 1, j2)
                i = j2
            continue

        i += 1
    return "".join(chars)


def _lex_python_tokenize(code: str) -> str | None:
    """tokenize-based Python stripping; None when tokenize cannot handle the input."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
    except Exception:
        return None
    # convert tokenize (row, col) to flat offsets (rows are \n-separated, 1-based)
    lines = code.split("\n")
    prefix = [0]
    for ln in lines:
        prefix.append(prefix[-1] + len(ln) + 1)

    def _off(row: int, col: int) -> int:
        return min(prefix[row - 1] + col, len(code))

    chars = list(code)
    fstart = getattr(tokenize, "FSTRING_START", None)
    fmid = getattr(tokenize, "FSTRING_MIDDLE", None)
    fend = getattr(tokenize, "FSTRING_END", None)
    fstring_types = {t for t in (fstart, fmid, fend) if t is not None}
    for tok in tokens:
        is_comment = tok.type == tokenize.COMMENT
        is_string = tok.type == tokenize.STRING
        is_ftext = fmid is not None and tok.type == fmid
        is_fdelim = fstart is not None and tok.type in (fstart, fend)
        if not (is_comment or is_string or is_ftext or is_fdelim):
            continue
        s, e = _off(*tok.start), _off(*tok.end)
        if e <= s:
            continue
        if is_comment or is_ftext:
            _blank_region(chars, s, e)
        else:
            # STRING / f-string delimiters: keep the two delimiter chars, blank the interior
            _blank_region(chars, s + 1, e - 1)
    return "".join(chars)


def strip_code(code: str, language: str) -> str | None:
    """Return the code-shape text (comments + string contents blanked).

    Returns None for languages without stripping support — callers then match
    against the raw code (previous behavior).
    """
    if language == "python":
        stripped = _lex_python_tokenize(code)
        if stripped is not None:
            return stripped
        return _scan_strip(code, line_comments=("#",), block_comments=(),
                           string_delims="'\"", triple_delims=("'''", '"""'))
    if language == "js":
        return _scan_strip(code, line_comments=("//",), block_comments=(("/*", "*/"),),
                           string_delims="'\"`", triple_delims=())
    return None
