async def get_all_datasets(datasette):
    db = datasette.get_database("portal")
    query = """
     SELECT *
       FROM databases
    """
    result = await db.execute(query)
    return [dict(row) for row in result]
  
async def get_dataset_by_id(datasette, dataset_id):
    db = datasette.get_database("portal")
    query = """
     SELECT *
       FROM databases
      WHERE db_id=(?)
    """
    result = await db.execute(query, (dataset_id,))
    return dict(result.first())
    