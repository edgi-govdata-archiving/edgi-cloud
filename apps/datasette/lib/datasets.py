async def get_all_datasets(datasette):
    db = datasette.get_database("portal")
    query = """
     SELECT *
       FROM databases
    """
    result = await db.execute(query)
    return [dict(row) for row in result]
    