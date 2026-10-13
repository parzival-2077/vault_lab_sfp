from app.models.models import AuditEvent

#записывает действия пользователя в AuditEvent
def write_event(
    db,
    event_type,
    actor_id=None,
    client_id=None,
    ip=None,
    user_agent=None,
    metadata=None,
    commit=True
):
    event = AuditEvent(
        event_type=event_type,
        actor_id=actor_id,
        client_id=client_id,
        ip=ip,
        user_agent=user_agent,
        metadata_json=metadata or {}
    )

    db.add(event)

    if commit:
        db.commit()

    return event