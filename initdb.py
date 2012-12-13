import psycopg2


conn = psycopg2.connect(database='flid')

cur = conn.cursor()
cur.execute("""CREATE TABLE openid_associations (
    handle CHARACTER VARYING NOT NULL UNIQUE,
    private BOOLEAN NOT NULL DEFAULT FALSE,
    secret BYTEA NOT NULL,
    assoc_type CHARACTER VARYING NOT NULL,
    expires TIMESTAMP NOT NULL
)""")
conn.commit()
