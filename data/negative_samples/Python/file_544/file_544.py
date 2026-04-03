import logging
logger = logging.getLogger(__name__)

from bottle import route, get, post, put, delete
from bottle import request, response

def error(code, message):
    response.status = code
    message['status'] = code
    return message


get_user_table = lambda db: db.get_table('users', primary_id='userid', primary_type='String(100)')


@delete('/groups/<group_name>')
def delete_group(db, group_name):
    groups_table = db.get_table('groups')
    group = groups_table.find_one(name=group_name)
    if not group:
        return error(404, {'error': 'group not found'})
    else:
        groups_table.delete(name=group_name)
        return {'status': 200}


@get('/groups/<group_name>')
def get_group(db, group_name):
    groups_table = db.get_table('groups')
    group = groups_table.find(name=group_name)
    rows = [x for x in group]
    if not rows:
        return error(404, {'error': 'Not a valid group'})

    userids = [x['userid'] for x in rows if x['userid']]
    if not userids:
        return {group_name: []}

    params = {}
    for i, userid in enumerate(userids,1):
        params['userid_' + str(i)] = str(userid)
    where_clause = 'userid IN(:' + ",:".join(params.keys()) + ')' # b/c sqlalchemy can't use a list!?
    q = "SELECT * FROM users WHERE " + where_clause
    users = db.executable.execute(q, params).fetchall()
    ret = {group_name: [dict(x.items()) for x in users] }
    return ret


@route('/groups/<group_name>', method=['POST', 'PUT'])
def post_group(db, group_name):
    groups_table = db.get_table('groups')
    group_exist = groups_table.find_one(name=group_name)
    #CREATE
    if request.method=='POST':
        if group_exist:
            return error(409, {'error': 'Group already exists'})
        else:
            groups_table.insert(dict(name=group_name, userid=None))
            return {'status': 200}

    #UPDATE
    elif request.method == 'PUT':
        if not group_exist:
            return error(400, {'error': 'Group does not exist'})
        else:
            userids = request.json.get('userids')
            if not userids:
                return error(400, {'error': 'Need a userids key'})

            user_table = get_user_table(db)
            groups_table.delete(name=group_name)
            unknown_users = []
            for userid in userids:
                user = user_table.find_one(userid=userid)
                if not user:
                    unknown_users.append(userid)
                else:
                    groups_table.insert(dict(name=group_name, userid=userid))

            ret = {'status': 200}
            if unknown_users:
                ret = { 'status': 207, 'unknown_users': unknown_users }
            return ret
