"""Retrieve an immutable public synthetic release. No token required."""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from urllib.parse import urlsplit

HASHES = {"v1":"07966d3b162dcaa33a04f0447021e9e768c0406c29eebb2cae1cd65e5acc302c",
          "v2":"f1b48c1578f46a0c55b06a8d4922d909ce4d428251ee68fff2c0279204fe3753"}

def sha(data):
    return hashlib.sha256(data).hexdigest()

ALLOWED_HOSTS = {
    "api.github.com", "github.com", "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


def validate_url(url):
    target = urlsplit(url)
    if target.scheme != "https" or target.netloc.lower() not in ALLOWED_HOSTS:
        raise ValueError("destination outside policy")


class CheckedRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def get(url, limit):
    validate_url(url)
    opener = build_opener(ProxyHandler({}), CheckedRedirect())
    request = Request(url, headers={"User-Agent": "synthetic-recovery"})
    with opener.open(request, timeout=20) as result:
        validate_url(result.url)
        if result.status != 200:
            raise ValueError("unexpected response")
        data = result.read(limit + 1)
    if len(data) > limit:
        raise ValueError("size limit")
    return data


def asset(m, repo, version):
    tag = "lab312-" + version
    url = f"https://github.com/{repo}/releases/download/{tag}/{version}.json"
    if m["tag_name"] != tag or m["immutable"] is not True or m["draft"] is not False or m["prerelease"] is not False:
        raise ValueError("unexpected release")
    a, = [item for item in m["assets"] if item["name"] == version + ".json"]
    if (a["browser_download_url"], a["state"], a["digest"]) != (url, "uploaded", "sha256:" + HASHES[version]):
        raise ValueError("unexpected asset")
    for number in (m["id"], a["id"], a["size"]):
        if type(number) is not int or number <= 0:
            raise ValueError("invalid numeric metadata")
    for value in (m["published_at"], a["updated_at"]):
        if not isinstance(value, str) or datetime.fromisoformat(value).utcoffset() is None:
            raise ValueError("timestamp without timezone")
    return a

def collect(dest, repo, version, commit, environment, run=None, fetch=get, clock=lambda:datetime.now(timezone.utc).isoformat()):
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+",repo) or not re.fullmatch("[a-f0-9]{40}",commit):
        raise ValueError("invalid repository or commit")
    dest.mkdir()
    tag = "lab312-" + version
    stage = "METADATA"
    try:
        started = clock()
        release_url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
        metadata = fetch(release_url, 512000)
        release = json.loads(metadata)
        item = asset(release, repo, version)
        stage = "ASSET"
        data = fetch(item["browser_download_url"], 4096)
        received = clock()
        digest = sha(data)
        if digest != HASHES[version] or len(data) != item["size"]:
            raise ValueError("asset mismatch")

        # Both responses remain in bounded memory until all checks pass.
        stage = "OUTPUT"
        report = dict(result="OK", repo=repo, version=version, commit=commit,
                      environment=environment, run=run, tag=tag, started=started,
                      received=received, release_url=release_url, release_id=release["id"],
                      asset_id=item["id"], url=item["browser_download_url"], sha256=digest,
                      published=release["published_at"], updated=item["updated_at"],
                      metadata_sha256=sha(metadata))
        (dest/"release.json").write_bytes(metadata)
        (dest/"asset.json").write_bytes(data)
        (dest/"receipt.json").write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    except Exception:
        # The destination was reserved by mkdir(). Only remove our own output files.
        for name in ("release.json", "asset.json", "receipt.json"):
            (dest/name).unlink(missing_ok=True)
        diagnostic = {"result": "FAILED", "stage": stage}
        (dest/"diagnostic.json").write_text(json.dumps(diagnostic), encoding="utf-8")
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("repo")
    parser.add_argument("version",choices=HASHES)
    parser.add_argument("commit")
    parser.add_argument("dest",type=Path)
    args = parser.parse_args()
    remote = os.environ.get("GITHUB_ACTIONS") == "true"
    if not remote and sys.platform != "win32":
        parser.error("local collector requires Windows")
    try:
        collect(args.dest,args.repo,args.version,args.commit,"actions" if remote else "windows",
                os.environ["GITHUB_RUN_ID"]+"/"+os.environ["GITHUB_RUN_ATTEMPT"] if remote else None)
    except Exception:
        sys.exit("Recovery failed")
