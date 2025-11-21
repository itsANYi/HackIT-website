from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import random
import string

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

# Avatar upload settings
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
AVATAR_FOLDER = os.path.join(app.static_folder, 'images', 'avatars')
os.makedirs(AVATAR_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 資料庫初始化
def init_db():
    conn = sqlite3.connect('hackers_it.db')
    c = conn.cursor()
    
    # 使用者表
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        nickname TEXT,
        avatar TEXT DEFAULT 'default-avatar.png',
        interests TEXT,
        question1 TEXT,
        question2 TEXT,
        question3 TEXT,
        installed BOOLEAN DEFAULT 0
    )''')
    
    conn.commit()
    conn.close()

init_db()

# 首頁
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

# 登入頁面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('hackers_it.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': '帳號或密碼錯誤'})
    
    return render_template('login.html')

# 註冊
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('hackers_it.db')
    c = conn.cursor()
    
    try:
        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                  (username, hashed_password))
        conn.commit()
        
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        session['user_id'] = user[0]
        session['username'] = username
        
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'message': '使用者名稱已存在'})

# 登出
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# 社團介紹（系統安裝）
@app.route('/installation')
def installation():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('installation.html')

# 儲存安裝資訊
@app.route('/save-installation', methods=['POST'])
def save_installation():
    if 'user_id' not in session:
        return jsonify({'success': False})
    
    data = request.json
    conn = sqlite3.connect('hackers_it.db')
    c = conn.cursor()
    c.execute('UPDATE users SET nickname = ?, installed = 1 WHERE id = ?',
              (data.get('nickname', ''), session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# 使用者資訊頁面
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('hackers_it.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

# 更新使用者資訊
@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'success': False})
    
    data = request.json
    conn = sqlite3.connect('hackers_it.db')
    c = conn.cursor()
    c.execute('''UPDATE users SET nickname = ?, interests = ?, 
                 question1 = ?, question2 = ?, question3 = ? WHERE id = ?''',
              (data.get('nickname', ''), data.get('interests', ''),
               data.get('question1', ''), data.get('question2', ''),
               data.get('question3', ''), session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})


# 上傳頭貼
@app.route('/upload-avatar', methods=['POST'])
def upload_avatar():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登入'}), 401

    if 'avatar' not in request.files:
        return jsonify({'success': False, 'message': '未選擇檔案'}), 400

    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'message': '檔案名稱無效'}), 400

    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': '僅允許上傳圖片檔 (png, jpg, jpeg, gif)'}), 400

    filename = secure_filename(file.filename)
    # 為避免檔名衝突，加入使用者 id 和隨機字串
    name, ext = os.path.splitext(filename)
    unique = f"user{session['user_id']}_{secrets.token_hex(8)}{ext}"
    save_path = os.path.join(AVATAR_FOLDER, unique)
    file.save(save_path)

    # 更新資料庫
    conn = sqlite3.connect('hackers_it.db')
    c = conn.cursor()
    c.execute('UPDATE users SET avatar = ? WHERE id = ?', (unique, session['user_id']))
    conn.commit()
    conn.close()

    avatar_url = url_for('static', filename=f'images/avatars/{unique}')
    return jsonify({'success': True, 'avatar': avatar_url})


# 修改密碼
@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登入'}), 401

    data = request.json or {}
    old = data.get('old_password', '')
    new = data.get('new_password', '')

    if not old or not new:
        return jsonify({'success': False, 'message': '請提供舊密碼與新密碼'}), 400

    conn = sqlite3.connect('hackers_it.db')
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': '使用者不存在'}), 404

    hashed = row[0]
    if not check_password_hash(hashed, old):
        conn.close()
        return jsonify({'success': False, 'message': '舊密碼錯誤'}), 400

    new_hashed = generate_password_hash(new)
    c.execute('UPDATE users SET password = ? WHERE id = ?', (new_hashed, session['user_id']))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': '密碼已更新'})

# 社團活動（問答遊戲）
@app.route('/activity')
def activity():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('activity.html')

# WebSocket 事件處理
waiting_users = []
active_games = {}
user_room_map = {}

@socketio.on('find_match')
def handle_find_match():
    user_id = session.get('user_id')
    username = session.get('username')
    
    print(f"[v0] find_match called by user_id: {user_id}, username: {username}")
    
    if not user_id or not username:
        print(f"[v0] User not logged in")
        emit('error', {'message': '請先登入'})
        return
    
    if user_id in [u['user_id'] for u in waiting_users]:
        print(f"[v0] User {user_id} already in waiting list")
        return
    
    if waiting_users:
        partner = waiting_users.pop(0)
        room_id = f"game_{user_id}_{partner['user_id']}"
        
        print(f"[v0] Match found! Room: {room_id}, Player1: {partner['username']}, Player2: {username}")
        
        active_games[room_id] = {
            'player1': {'user_id': partner['user_id'], 'username': partner['username'], 'sid': partner['sid']},
            'player2': {'user_id': user_id, 'username': username, 'sid': request.sid},
            'round': 1,
            'messages': [],
            'round_state': {
                'player1_asked': False,
                'player1_answered': False,
                'player2_asked': False,
                'player2_answered': False,
                'player1_ready': False,
                'player2_ready': False
            }
        }
        # map users to room so they can reconnect
        user_room_map[partner['user_id']] = room_id
        user_room_map[user_id] = room_id
        
        join_room(room_id, sid=partner['sid'])
        join_room(room_id, sid=request.sid)
        
        emit('match_found', {
            'room_id': room_id,
            'partner': username,
            'you_are': 'player2'
        }, room=partner['sid'])
        
        emit('match_found', {
            'room_id': room_id,
            'partner': partner['username'],
            'you_are': 'player1'
        }, room=request.sid)
    else:
        print(f"[v0] User {user_id} added to waiting list")
        waiting_users.append({
            'user_id': user_id,
            'username': username,
            'sid': request.sid
        })
        emit('waiting', {'message': '正在尋找配對對象...'})


@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    if not user_id:
        return

    # If user has an active room, re-associate this sid and join the room
    room_id = user_room_map.get(user_id)
    if room_id and room_id in active_games:
        game = active_games[room_id]
        # determine player role
        if game['player1']['user_id'] == user_id:
            player_key = 'player1'
            other_key = 'player2'
        else:
            player_key = 'player2'
            other_key = 'player1'

        # update sid and join room
        game[player_key]['sid'] = request.sid
        join_room(room_id, sid=request.sid)

        # prepare local state for this player
        local_state = {
            'askedThisRound': game['round_state'].get(f"{player_key}_asked", False),
            'answeredThisRound': game['round_state'].get(f"{player_key}_answered", False),
            'roundComplete': False,
            'readyForNext': game['round_state'].get(f"{player_key}_ready", False)
        }
        # compute roundComplete
        rs = game['round_state']
        local_state['roundComplete'] = (rs['player1_asked'] and rs['player1_answered'] and rs['player2_asked'] and rs['player2_answered'])

        # send reconnect state only to this sid
        emit('reconnect_state', {
            'room_id': room_id,
            'partner': game[other_key]['username'],
            'you_are': player_key,
            'round': game['round'],
            'messages': game.get('messages', []),
            'localState': local_state
        }, room=request.sid)

        # notify other player that this user reconnected
        other_sid = game[other_key].get('sid')
        if other_sid:
            emit('player_reconnected', {'player': game[player_key]['username']}, room=other_sid)

@socketio.on('send_message')
def handle_message(data):
    room_id = data['room_id']
    message = data['message']
    message_type = data.get('type', 'question')  # 'question' or 'answer'
    
    if room_id not in active_games:
        return
    
    game = active_games[room_id]
    user_id = session.get('user_id')
    
    # 確定玩家角色
    if game['player1']['user_id'] == user_id:
        player_key = 'player1'
        other_player_key = 'player2'
    else:
        player_key = 'player2'
        other_player_key = 'player1'
    
    round_state = game['round_state']
    
    # 檢查是否可以發送此類型的訊息
    can_send = False
    if message_type == 'question' and not round_state[f'{player_key}_asked']:
        can_send = True
        round_state[f'{player_key}_asked'] = True
    elif message_type == 'answer' and not round_state[f'{player_key}_answered']:
        can_send = True
        round_state[f'{player_key}_answered'] = True
    
    if not can_send:
        emit('message_blocked', {
            'message': '本輪你已經發送過此類型的訊息了！'
        }, room=request.sid)
        return
    
    # store message in game history
    game['messages'].append({'from': session.get('username'), 'message': message, 'type': message_type})

    # 發送訊息
    emit('receive_message', {
        'message': message,
        'from': session.get('username'),
        'type': message_type
    }, room=room_id, skip_sid=request.sid)
    
    # 檢查是否雙方都完成了提問和回答
    round_complete = (
        round_state['player1_asked'] and 
        round_state['player1_answered'] and 
        round_state['player2_asked'] and 
        round_state['player2_answered']
    )
    
    if round_complete:
        emit('round_complete', {
            'message': '本輪完成！雙方都按下「下一輪」按鈕即可繼續'
        }, room=room_id)

@socketio.on('next_round')
def handle_next_round(data):
    room_id = data['room_id']
    if room_id not in active_games:
        return
    
    game = active_games[room_id]
    user_id = session.get('user_id')
    
    # 確定玩家角色
    if game['player1']['user_id'] == user_id:
        player_key = 'player1'
    else:
        player_key = 'player2'
    
    # 標記玩家準備好
    game['round_state'][f'{player_key}_ready'] = True
    
    # 通知房間內有人準備好了
    emit('player_ready', {
        'player': session.get('username')
    }, room=room_id)
    
    # 檢查是否雙方都準備好
    if game['round_state']['player1_ready'] and game['round_state']['player2_ready']:
        game['round'] += 1
        # 重置輪次狀態
        game['round_state'] = {
            'player1_asked': False,
            'player1_answered': False,
            'player2_asked': False,
            'player2_answered': False,
            'player1_ready': False,
            'player2_ready': False
        }
        emit('round_updated', {
            'round': game['round']
        }, room=room_id)

@socketio.on('end_game')
def handle_end_game(data):
    room_id = data['room_id']
    emit('game_ended', {'message': '遊戲結束！'}, room=room_id)
    if room_id in active_games:
        del active_games[room_id]

@socketio.on('disconnect')

def handle_disconnect():
    global waiting_users
    user_id = session.get('user_id')
    # remove from waiting list
    waiting_users = [u for u in waiting_users if u['user_id'] != user_id]

    # if user was in an active game, mark their sid as None and notify partner
    room_id = user_room_map.get(user_id)
    if room_id and room_id in active_games:
        game = active_games[room_id]
        if game['player1']['user_id'] == user_id:
            game['player1']['sid'] = None
            other_sid = game['player2'].get('sid')
            if other_sid:
                emit('partner_disconnected', {'message': '對手已離線'}, room=other_sid)
        elif game['player2']['user_id'] == user_id:
            game['player2']['sid'] = None
            other_sid = game['player1'].get('sid')
            if other_sid:
                emit('partner_disconnected', {'message': '對手已離線'}, room=other_sid)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
