"""Hidden-query title search with Unicode equivalence, scopes and durable audit."""
import pathlib
import sys
import tempfile
from personal_acceptance import invoke


def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        path = str(pathlib.Path(tmp) / "owner.ll")
        pw, secret = "synthetic-master-password", "password-only-needle"
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw), ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        for title in ("Straße Café 中文", "Straße Café 中文", "Straße archived", "safe\u202e中文"):
            invoke(binary, "add-login", path, factors + [("登录标题", title), ("用户名（可留空）", "username-only-needle"), ("登录密码", secret)])
        rows = invoke(binary, "list", path, factors)[0]
        archived = rows[2]
        invoke(binary, "archive-login", path, factors + [("输入 SAVE 确认更改归档状态", "SAVE")], options=("--id", archived["id"], "--revision", archived["revision"]))
        before = invoke(binary, "list", path, factors, options=("--state", "all"))[0]
        prompt = "搜索标题（隐藏输入）"
        first = invoke(binary, "search", path, factors + [(prompt, "STRASSE")], forbidden=(secret, "username-only-needle", "STRASSE"))[0]
        assert len(first["rows"]) == 2 and first["scope"] == "active"
        assert len({row["id"] for row in first["rows"]}) == 2
        equivalent = invoke(binary, "search", path, factors + [(prompt, "Cafe\u0301")], forbidden=(secret,))[0]
        assert equivalent["rows"] == first["rows"] and equivalent["query_digest"] != first["query_digest"]
        all_rows = invoke(binary, "search", path, factors + [(prompt, "STRASSE")], options=("--state", "all"), forbidden=(secret, "STRASSE"))[0]
        assert len(all_rows["rows"]) == 3 and all_rows["query_digest"] != first["query_digest"]
        unsafe = invoke(binary, "search", path, factors + [(prompt, "safe")], forbidden=(secret, "\u202e"))[0]
        assert unsafe["rows"][0]["title"] == "safe\u202e中文"
        no_match = invoke(binary, "search", path, factors + [(prompt, secret)], forbidden=(secret,))[0]
        assert no_match["rows"] == [] and "query" not in no_match
        invoke(binary, "search", path, factors + [(prompt, "\u202e")], ok=False, expect_error="invalid title search", forbidden=("\u202e", secret))
        invoke(binary, "search", path, [("主密码", pw + "wrong"), factors[1], (prompt, "STRASSE")], ok=False, expect_error="invalid personal vault", forbidden=("STRASSE", secret))
        assert invoke(binary, "list", path, factors, options=("--state", "all"))[0] == before
        events = invoke(binary, "audit", path, factors, forbidden=("STRASSE", "Cafe\u0301", secret))[0]
        searches = [event for event in events if event["action"] == "item.search"]
        assert len(searches) == 5 and all(event["result"] == "succeeded" for event in searches)
        assert searches[0]["link"] == first["query_digest"] and searches[0]["session"] == first["session"]
        assert all("query" not in event for event in events)
    print("PASS: hidden Unicode title search, duplicate IDs, state scope, safe JSON, no secret-field match, durable audit and stable revisions")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
