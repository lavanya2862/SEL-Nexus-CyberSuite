import pytest

from remediation.github import RepoURLError, parse_repo_url


@pytest.mark.parametrize("url,owner,name,ref", [
    ("https://github.com/octo/demo", "octo", "demo", None),
    ("https://github.com/octo/demo.git", "octo", "demo", None),
    ("https://www.github.com/octo/demo/", "octo", "demo", None),
    ("github.com/octo/demo", "octo", "demo", None),
    ("git@github.com:octo/demo.git", "octo", "demo", None),
    ("ssh://git@github.com/octo/demo.git", "octo", "demo", None),
    ("https://github.com/octo/demo/tree/feature/login", "octo", "demo", "feature/login"),
    ("https://github.com/octo/demo/commit/0123abcd", "octo", "demo", "0123abcd"),
    ("https://github.com/octo/demo/blob/main/src/app.py", "octo", "demo", "main"),
    ("https://github.com/octo/demo/releases/tag/v1.2.0", "octo", "demo", "v1.2.0"),
    ("https://github.com/octo/demo?tab=readme#top", "octo", "demo", None),
])
def test_accepts_common_github_links(url, owner, name, ref):
    repo = parse_repo_url(url)
    assert (repo.owner, repo.name, repo.ref) == (owner, name, ref)
    assert repo.clone_url == f"https://github.com/{owner}/{name}.git"


@pytest.mark.parametrize("url", [
    "", "not a url", "https://gitlab.com/octo/demo", "http://github.com/octo/demo", "https://github.com/octo",
    "file:///etc/passwd", "https://user:pass@github.com/octo/demo", "https://github.com/../etc",
    "https://github.com/octo/demo/tree/--upload-pack=evil", "https://github.com/octo/de mo",
    "https://evil.com/github.com/octo/demo", "https://github.com.evil.com/octo/demo",
])
def test_rejects_unsafe_or_foreign_input(url):
    with pytest.raises(RepoURLError):
        parse_repo_url(url)


def test_explicit_ref_overrides_url_ref():
    assert parse_repo_url("https://github.com/o/r/tree/dev", ref="main").ref == "main"


def test_rejects_bad_ref():
    with pytest.raises(RepoURLError):
        parse_repo_url("https://github.com/o/r", ref="a..b")
