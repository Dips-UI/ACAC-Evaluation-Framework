"""Acyclic artifact hash-dependency checks."""


def validate_hash_dependencies(edges: dict[str, list[str]]) -> None:
    visiting = set(); visited = set()
    def visit(node):
        if node in visiting: raise ValueError("hash_dependency_cycle")
        if node in visited: return
        visiting.add(node)
        for child in edges.get(node, []): visit(child)
        visiting.remove(node); visited.add(node)
    for node in edges: visit(node)
    if any("freeze_event" in child for child in edges.get("manifest", [])):
        raise ValueError("manifest_freeze_hash_forbidden")
