#!/usr/bin/env python3
"""Détecteur de fichiers doublons.

Scanne un ou plusieurs répertoires/disques et regroupe les fichiers
identiques (même taille puis même empreinte cryptographique).

Par défaut : simple rapport. Actions possibles (mutuellement exclusives) :
  --move-to DOSSIER   déplace les copies en trop vers DOSSIER
  --delete            supprime les copies en trop (confirmation requise
                      sauf avec --yes)
"""

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from fnmatch import fnmatch

CHUNK = 1024 * 1024
PARTIAL_BYTES = 1024 * 1024


def parse_size(text):
    text = str(text).strip().upper()
    mult = 1
    if text and text[-1] in "KMGT":
        mult = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}[text[-1]]
        text = text[:-1]
    return int(float(text) * mult)


def human_size(n):
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or unit == "To":
            return f"{n:.1f} {unit}" if unit != "o" else f"{n} o"
        n /= 1024
    return f"{n} o"


def excluded(path, patterns):
    if not patterns:
        return False
    parts = path.split(os.sep)
    for pat in patterns:
        if fnmatch(path, pat) or any(fnmatch(p, pat) for p in parts):
            return True
    return False


def iter_files(roots, patterns, follow_links):
    seen = set()
    for root in roots:
        root = os.path.abspath(root)
        if os.path.isfile(root):
            yield root
            continue
        if not os.path.isdir(root):
            print(f"[warn] chemin ignoré (introuvable) : {root}", file=sys.stderr)
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
            dirnames[:] = sorted(
                d for d in dirnames
                if not excluded(os.path.join(dirpath, d), patterns)
            )
            for name in sorted(filenames):
                path = os.path.join(dirpath, name)
                if excluded(path, patterns):
                    continue
                if not follow_links and os.path.islink(path):
                    continue
                try:
                    st = os.stat(path, follow_symlinks=follow_links)
                except OSError as e:
                    print(f"[warn] lecture impossible : {path} ({e.strerror})", file=sys.stderr)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                key = (st.st_dev, st.st_ino)
                if key in seen:
                    continue
                seen.add(key)
                yield path, st.st_size


def _read_head_tail(path, n):
    size = os.path.getsize(path)
    head = b""
    tail = b""
    with open(path, "rb") as f:
        head = f.read(min(n, size))
        if size > n:
            f.seek(max(0, size - n))
            tail = f.read(n)
    return head + tail


def partial_hash(path, algo):
    h = hashlib.new(algo)
    try:
        h.update(_read_head_tail(path, PARTIAL_BYTES))
    except OSError:
        return None
    return h.hexdigest()


def full_hash(path, algo):
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def group_by(items, keyfunc, workers):
    groups = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for path, value in zip(items, pool.map(keyfunc, items)):
            if value is None:
                continue
            groups.setdefault(value, []).append(path)
    return {k: v for k, v in groups.items() if len(v) > 1}


def find_duplicates(roots, patterns, follow_links, algo, min_size, workers, progress):
    files = []
    for path, size in iter_files(roots, patterns, follow_links):
        if size >= min_size:
            files.append((path, size))
    if progress:
        print(f"{len(files)} fichiers scannés (taille >= {human_size(min_size)})", file=sys.stderr)

    by_size = {}
    for path, size in files:
        by_size.setdefault(size, []).append(path)
    candidates = [p for size, paths in by_size.items() if len(paths) > 1 for p in paths]
    if progress:
        print(f"{len(candidates)} fichiers candidats (taille partagée)", file=sys.stderr)

    by_partial = group_by(candidates, lambda p: partial_hash(p, algo), workers)
    size_of = dict(files)
    partial_keyed = {}
    for ph, paths in by_partial.items():
        for p in paths:
            partial_keyed.setdefault((size_of[p], ph), []).append(p)
    partial_keyed = {k: v for k, v in partial_keyed.items() if len(v) > 1}
    to_confirm = [p for paths in partial_keyed.values() for p in paths]
    if progress:
        print(f"{len(to_confirm)} fichiers à empreinte complète", file=sys.stderr)

    by_full = group_by(to_confirm, lambda p: full_hash(p, algo), workers)
    full_keyed = {}
    for fh, paths in by_full.items():
        for p in paths:
            full_keyed.setdefault((size_of[p], fh), []).append(p)

    results = []
    for (size, fh), paths in full_keyed.items():
        if len(paths) > 1:
            results.append({"size": size, "hash": fh, "files": sorted(paths)})
    results.sort(key=lambda g: g["size"] * (len(g["files"]) - 1), reverse=True)
    return results, len(files)


def unique_dest(directory, path):
    base = os.path.basename(path)
    dest = os.path.join(directory, base)
    i = 1
    while os.path.exists(dest):
        dest = os.path.join(directory, f"{base}.{i}")
        i += 1
    return dest


def apply_action(results, action, dest_dir, assume_yes):
    moved = deleted = 0
    for group in results:
        files = sorted(group["files"], key=lambda p: os.path.getmtime(p))
        keep = files[0]
        for path in files[1:]:
            try:
                if action == "move":
                    os.makedirs(dest_dir, exist_ok=True)
                    shutil.move(path, unique_dest(dest_dir, path))
                    moved += 1
                elif action == "delete":
                    if not assume_yes:
                        ans = input(f"Supprimer {path} ? [o/N] ")
                        if ans.strip().lower() not in ("o", "oui", "y", "yes"):
                            continue
                    os.remove(path)
                    deleted += 1
                print(f"{'déplacé' if action == 'move' else 'supprimé'} : {path} (conservé : {keep})")
            except OSError as e:
                print(f"[warn] échec sur {path} : {e}", file=sys.stderr)
    return moved, deleted


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="find_duplicates",
        description="Identifie tous les fichiers doublons sur les disques/répertoires donnés.",
    )
    ap.add_argument("paths", nargs="+", help="Disques ou répertoires à scanner (ex: / /mnt/donnees ~)")
    ap.add_argument("--min-size", default="0", help="Taille minimale, ex: 1K, 10M, 1G (défaut: 0)")
    ap.add_argument("--algo", default="sha256",
                    choices=sorted(hashlib.algorithms_available),
                    help="Algorithme d'empreinte (défaut: sha256)")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Motif glob à exclure (répétable), ex: --exclude '*.tmp' --exclude '/proc/*'")
    ap.add_argument("--follow-links", action="store_true",
                    help="Suivre les liens symboliques (désactivé par défaut)")
    ap.add_argument("--threads", type=int, default=min(8, (os.cpu_count() or 4)),
                    help="Nombre de threads de hachage (défaut: min(8, cœurs))")
    ap.add_argument("--json", metavar="FICHIER", help="Écrit aussi le rapport en JSON dans FICHIER")
    ap.add_argument("--move-to", metavar="DOSSIER",
                    help="Déplace les copies en trop vers DOSSIER (le plus ancien fichier est conservé)")
    ap.add_argument("--delete", action="store_true",
                    help="Supprime les copies en trop (le plus ancien fichier est conservé)")
    ap.add_argument("--yes", action="store_true",
                    help="Avec --delete : pas de confirmation interactive")
    ap.add_argument("--quiet", action="store_true", help="Masque la progression")
    args = ap.parse_args(argv)

    if args.move_to and args.delete:
        ap.error("--move-to et --delete sont mutuellement exclusifs")

    min_size = parse_size(args.min_size)
    results, total = find_duplicates(
        args.paths, args.exclude, args.follow_links, args.algo,
        min_size, max(1, args.threads), progress=not args.quiet,
    )

    groups = len(results)
    redundant = sum(len(g["files"]) - 1 for g in results)
    wasted = sum(g["size"] * (len(g["files"]) - 1) for g in results)

    print("\n=== Doublons trouvés ===")
    if not results:
        print("Aucun doublon.")
    for i, g in enumerate(results, 1):
        print(f"\nGroupe {i} — {len(g['files'])} fichiers de {human_size(g['size'])} "
              f"({g['algo'] if 'algo' in g else args.algo[:12]}: {g['hash'][:16]}…)")
        for p in g["files"]:
            print(f"  {p}")
    print(f"\nRésumé : {groups} groupe(s), {redundant} fichier(s) en trop, "
          f"{human_size(wasted)} récupérable(s). ({total} fichiers analysés)")

    if args.json:
        payload = {
            "groups": results,
            "summary": {"scanned": total, "groups": groups,
                        "redundant_files": redundant, "reclaimable_bytes": wasted},
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"Rapport JSON : {args.json}")

    if args.move_to:
        moved, _ = apply_action(results, "move", args.move_to, True)
        print(f"{moved} fichier(s) déplacé(s) vers {args.move_to}")
    elif args.delete:
        if not results:
            return 0
        if not args.yes:
            ans = input(f"\nSupprimer {redundant} fichier(s) en trop ? [o/N] ")
            if ans.strip().lower() not in ("o", "oui", "y", "yes"):
                print("Annulé.")
                return 0
            args.yes = True
        _, deleted = apply_action(results, "delete", None, args.yes)
        print(f"{deleted} fichier(s) supprimé(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
