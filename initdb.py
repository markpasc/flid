from openid.store import sqlstore
import psycopg2


conn = psycopg2.connect(database='flid')
store = sqlstore.PostgreSQLStore(conn)

store.createTables()
