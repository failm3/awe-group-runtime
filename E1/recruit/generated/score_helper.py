def score(skills):
    if not skills:
        return 0
    normalized = {skill.strip().lower() for skill in skills}
    skill_counts = {"javascript": 5, "sql": 3, "testing": 2}
    return sum(skill_counts.get(skill, 0) for skill in normalized)