from flask import Flask, render_template, session, redirect, url_for, request, flash,jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from bson import ObjectId
import json
import conexion



# -----------------CONEXIONES-----------------------
mongo = conexion.mongo_conexion()
redis = conexion.redis_conexion()

app = Flask(__name__)
app.secret_key = "miruta"


# -----------------NAVEGACIÓN-----------------------

# Enlace común para cerrar sesión
enlace_salir = {
    'texto': '<i class="fas fa-sign-out-alt"></i>&nbspSalir',
    'url': '/logout'
}

# Menú para administrador del sistema
navbar_admin = [
    {
        'texto': '<i class="fas fa-user-shield"></i>&nbspUsuarios',
        'url': '/usuarios'
    },
    {
        'texto': '<i class="fas fa-map-signs"></i>&nbspRutas',
        'url': '/rutas'
    },
    {
        'texto': '<i class="fas fa-user-tie"></i>&nbspConductores',
        'url': '/conductores'
    },
    enlace_salir
]

# Menú para conductores
navbar_conductor = [
    {
        'texto': '<i class="fas fa-road"></i>&nbspConducir',
        'url': '/conductor'
    },
    enlace_salir
]

# Menú para usuarios (pasajeros)
def navbar_usuario():
    if 'usuario' not in session:
        return []

    return [
        {
            'texto': '<i class="fas fa-user-edit"></i>&nbspActualizar',
            'url': f"/actualizar_usuario/{session['usuario']['_id']}"
        },
        enlace_salir
    ]





# ---------------------- LOGIN ----------------------

@app.route('/login', methods=['POST'])
def login():
    ci = request.form['ci']
    password = request.form['password']

    usuario = mongo['usuarios'].find_one({'ci': ci})

    if usuario and check_password_hash(usuario['password'], password):
        session['usuario'] = {
            '_id': str(usuario['_id']),
            'nombre': usuario['nombre'],
            'ci': usuario['ci'],
            'rol': usuario['rol'],
            'email': usuario['email'],
            'fechaNac': usuario.get('fechaNac')
        }
        flash(f"Bienvenido {usuario['nombre']}")
    else:
        flash('Usuario no Registrado o contraseña incorrecta')

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada')
    return redirect(url_for('index'))

# ---------------------- PÁGINA PRINCIPAL ----------------------

@app.route('/')
def index():


    if session.get('usuario'):
        nombre = session['usuario']['nombre']

        if session['usuario']['rol'] == 'sysadmin':
            return render_template('mapa_trafico.html', title="Administrador de Sistema", navbar=navbar_admin, nombre=nombre)
        
        if session['usuario']['rol'] == 'usuario':
            return render_template('mapa_trafico.html', title="Usuario", navbar=navbar_usuario(), nombre=nombre)
        
        if session['usuario']['rol'] == 'conductor':
            
            return render_template('mapa_trafico.html', title="Usuario", navbar=navbar_conductor, nombre=nombre)
       
    return render_template('index.html', title="Mi Ruta")

# ---------------------- REGISTRO DE USUARIO ----------------------

@app.route('/crear_usuario', methods=['GET', 'POST'])
def crear_usuario():
    title = 'Registro de usuario'

    if request.method == 'POST':
        if mongo['usuarios'].find_one({'email': request.form['email']}):
            flash('Usuario ya registrado')
            return redirect(url_for('crear_usuario'))

        registro = {
            'nombre': request.form['nombre'],
            'ci': request.form['ci'],
            'email': request.form['email'],
            'password': generate_password_hash(request.form['password']),
            'rol': 'usuario',
            'fechaNac': request.form['fnac']
        }

        mongo['usuarios'].insert_one(registro)
        flash('Usuario registrado')
        return redirect(url_for('index'))

    return render_template('usuario/crud_usuario.html', title=title, tipo='crear', usuario=None,navbar=navbar_usuario())

# ---------------------- ACTUALIZACIÓN DE USUARIO ----------------------

@app.route('/actualizar_usuario/<id>', methods=['GET', 'POST'])
def actualizar_usuario(id):
    title = 'Actualización de usuario'

    if request.method == 'POST':
        actualizacion = {
            'nombre': request.form['nombre'],
            'ci': request.form['ci'],
            'email': request.form['email'],
            'fechaNac': request.form['fnac']
        }

        if request.form['password']:
            actualizacion['password'] = generate_password_hash(request.form['password'])

        mongo['usuarios'].update_one({'_id': ObjectId(id)}, {'$set': actualizacion})
        flash('Usuario actualizado')
        return redirect(url_for('index'))

    usuario = mongo['usuarios'].find_one({'_id': ObjectId(id)})
    return render_template('usuario/crud_usuario.html', title=title, tipo='actualizar', usuario=usuario,navbar=navbar_usuario())

# ---------------------- ELIMINACIÓN DE USUARIO ----------------------

@app.route('/eliminar_usuario/<id>')
def eliminar_usuario(id):
    if mongo['usuarios'].delete_one({'_id': ObjectId(id)}):
        flash('Usuario eliminado')
        session.clear()
    else:
        flash('Error al eliminar el usuario')
    return redirect(url_for('index'))

# ----------------------- SYSADMIN ----------------------

# ----------------------- Gestion de Usuarios ----------------------

@app.route('/usuarios', methods=['GET', 'POST'])
def vista_usuarios():
    if not session.get('usuario') or session['usuario']['rol'] != 'sysadmin':
        flash(session['usuario']['rol'])
        flash('Acceso no autorizado')
        return redirect(url_for('index'))

    if request.method == 'POST':
        data = {
            'nombre': request.form['nombre'],
            'ci': request.form['ci'],
            'email': request.form['email'],
            'rol': request.form['rol'],
            'fechaNac': request.form.get('fnac')  # opcional
        }

        if request.form.get('id'):  # actualizar
            if request.form['password']:
                data['password'] = generate_password_hash(request.form['password'])
            mongo['usuarios'].update_one({'_id': ObjectId(request.form['id'])}, {'$set': data})
            flash('Usuario actualizado')
        else:  # nuevo
            data['password'] = generate_password_hash(request.form['password'])
            mongo['usuarios'].insert_one(data)
            flash('Usuario creado')

        return redirect(url_for('vista_usuarios'))

    # GET con búsqueda y edición
    q = request.args.get('q', '').strip()
    filtro = {'$or': [{'nombre': {'$regex': q, '$options': 'i'}}, 
                      {'email': {'$regex': q, '$options': 'i'}},
                      {'ci': {'$regex': q, '$options': 'i'}},
                      {'rol': {'$regex': q, '$options': 'i'}}
                      ]} if q else {}
    usuarios = list(mongo['usuarios'].find(filtro))

    usuario_actual = None
    id_editar = request.args.get('edit')
    if id_editar:
        usuario_actual = mongo['usuarios'].find_one({'_id': ObjectId(id_editar)})

    return render_template('sysadmin/gestion_usuarios.html', usuarios=usuarios, query=q, usuario_actual=usuario_actual,nombre=session['usuario']['nombre'], navbar=navbar_admin)



@app.route('/usuarios/eliminar/<id>')
def eliminar_usuario_por_id(id):
    if not session.get('usuario') or session['usuario']['rol'] != 'sysadmin':
        flash('Acceso no autorizado')
        return redirect(url_for('index'))

    mongo['usuarios'].delete_one({'_id': ObjectId(id)})
    flash('Usuario eliminado')
    return redirect(url_for('vista_usuarios'))



# ---------------------- Gestion de Rutas ----------------------

@app.route('/rutas', methods=['GET', 'POST'])
def gestionar_rutas():
    if not session.get('usuario') or session['usuario']['rol'] != 'sysadmin':
        flash('Acceso no autorizado')
        return redirect(url_for('index'))

    q = request.args.get('q', '').strip()
    id_editar = request.args.get('edit')
    filtro = {'nombre': {'$regex': q, '$options': 'i'}} if q else {}
    rutas = list(mongo['rutas'].find(filtro))
    ruta_actual = mongo['rutas'].find_one({'_id': ObjectId(id_editar)}) if id_editar else None

    if request.method == 'POST':
        nombre = request.form['nombre']
        puntos = request.form['puntos']

        import json
        try:
            puntos_json = json.loads(puntos)
        except:
            flash('Error en los puntos seleccionados')
            return redirect(url_for('gestionar_rutas'))

        if request.form.get('id'):  # actualizar
            mongo['rutas'].update_one(
                {'_id': ObjectId(request.form['id'])},
                {'$set': {'nombre': nombre, 'puntos': puntos_json}}
            )
            flash('Ruta actualizada correctamente')
        else:  # nueva
            mongo['rutas'].insert_one({'nombre': nombre, 'puntos': puntos_json})
            flash('Ruta registrada correctamente')

        return redirect(url_for('gestionar_rutas'))

    return render_template('sysadmin/gestion_rutas.html', title='Gestión de rutas',
                           rutas=rutas, query=q, ruta_actual=ruta_actual,
                           nombre=session['usuario']['nombre'], navbar=navbar_admin)


@app.route('/rutas/eliminar/<id>')
def eliminar_ruta(id):
    if not session.get('usuario') or session['usuario']['rol'] != 'sysadmin':
        flash('Acceso no autorizado')
        return redirect(url_for('index'))

    mongo['rutas'].delete_one({'_id': ObjectId(id)})
    flash('Ruta eliminada')
    return redirect(url_for('gestionar_rutas'))


# ----------------------- Gestion de Conductores ----------------------

@app.route('/conductores', methods=['GET', 'POST'])
def vista_conductores():
    # Crear o actualizar
    if request.method == 'POST':
        id_conductor = request.form.get('id')
        usuario_id = ObjectId(request.form['usuario_id'])
        vehiculo = {
            'placa': request.form['vehiculo[placa]'],
            'marca': request.form.get('vehiculo[marca]', ''),
            'modelo': request.form.get('vehiculo[modelo]', ''),
            'color': request.form.get('vehiculo[color]', ''),
            'anio': int(request.form.get('vehiculo[anio]', 0)),
            'tipo': request.form.get('vehiculo[tipo]','')
        }
        rutas_raw = request.form.get('rutas', '[]')
        rutas_ids = json.loads(rutas_raw)
        rutas = [ObjectId(r) for r in rutas_ids]

        data = {
            'usuario_id': usuario_id,
            'vehiculo': vehiculo,
            'rutas': rutas
        }

        if id_conductor:
            mongo['conductores'].update_one({'_id': ObjectId(id_conductor)}, {'$set': data})
            flash('Conductor actualizado')
        else:
            mongo['conductores'].insert_one(data)
            flash('Conductor registrado')

        return redirect(url_for('vista_conductores'))

    # Listar + editar
    query = request.args.get('q', '').strip()
    filtro = {}
    if query:
        filtro = {
            '$or': [
                {'vehiculo.placa': {'$regex': query, '$options': 'i'}}
            ]
        }

    conductores = list(mongo['conductores'].find(filtro))

    # Traer datos relacionados
    for c in conductores:
        c['usuario'] = mongo['usuarios'].find_one({'_id': c['usuario_id']})
        c['rutas'] = list(mongo['rutas'].find({'_id': {'$in': c.get('rutas', [])}}))

    conductor_actual = None
    id_editar = request.args.get('edit')
    if id_editar:
        conductor_actual = mongo['conductores'].find_one({'_id': ObjectId(id_editar)})

    usuarios = list(mongo['usuarios'].find({'rol': 'conductor'}))
    rutas = list(mongo['rutas'].find({}))        

    return render_template('sysadmin/gestion_conductores.html',
                           conductores=conductores,
                           conductor_actual=conductor_actual,
                           usuarios=usuarios,
                           rutas=rutas,
                           query=query,
                           nombre=session['usuario']['nombre'],
                           navbar=navbar_admin
                           )


@app.route('/conductores/eliminar/<id>')
def eliminar_conductor(id):
    mongo['conductores'].delete_one({'_id': ObjectId(id)})
    flash('Conductor eliminado')
    return redirect(url_for('vista_conductores'))

# ------------------------ Vista Conductor ----------------------


# Ruta de inicio del conductor
@app.route('/conductor', methods=['GET'])
def vista_conductor():
    if session['usuario']['rol'] != 'conductor':
        flash('Acceso no autorizado')
        return redirect(url_for('index'))

    id_conductor = session['usuario']['_id']    
  
    doc = mongo['conductores'].find_one({'usuario_id': ObjectId(id_conductor)}, {'rutas': 1})
    rutas = []
    for ruta in doc['rutas']:
        rutas.append(mongo['rutas'].find_one({'_id': ruta}))
    navbar=[{'texto': '<i class="fas fa-sign-out-alt"></i> Salir', 'url': url_for('logout')}]
    return render_template('conductor/index.html', rutas=rutas, nombre=session['usuario']['nombre'],navbar=navbar_conductor)


# Iniciar ruta
@app.route('/api/conductor/iniciar', methods=['POST'])
def api_iniciar_ruta():
    if session['usuario']['rol'] != 'conductor':
        return jsonify({'error': 'Acceso no autorizado'}), 403

    data = request.get_json()
    id_ruta = data.get('ruta_id')
    id_usuario = session['usuario']['_id']

    # Verifica si ya tiene una ruta activa
    if redis.exists(f"conductor:{id_usuario}:ruta"):
        return jsonify({'error': 'Ruta ya iniciada'}), 400

    ruta = mongo['rutas'].find_one({'_id': ObjectId(id_ruta)})
    if not ruta:
        return jsonify({'error': 'Ruta no encontrada'}), 404

    # Clave única por conductor + ruta
    key_puntos = f"ruta:{id_ruta}:conductor:{id_usuario}:puntos"

    # Guardar puntos con GEOADD en Redis
    for i, punto in enumerate(ruta['puntos']):
        redis.geoadd(key_puntos, (punto['lng'], punto['lat'], f"p{i}"))
        redis.set(f"{key_puntos}:p{i}:desc", punto.get('desc', ''))

    # Asociar ruta activa al conductor
    redis.set(f"conductor:{id_usuario}:ruta", id_ruta)

    return jsonify({'mensaje': 'Ruta iniciada', 'nombre': ruta['nombre']})


# Cancelar ruta
@app.route('/api/conductor/cancelar', methods=['POST'])
def cancelar_ruta():
    id_conductor = session['usuario']['_id']
    ruta_id = redis.get(f"conductor:{id_conductor}:ruta")

    if ruta_id:
        # Clave específica del conjunto de puntos del conductor
        key_puntos = f"ruta:{ruta_id}:conductor:{id_conductor}:puntos"

        # Obtener puntos activos
        puntos = redis.zrange(key_puntos, 0, -1) 

        for punto in puntos:
            # Borrar descripciones individuales
            redis.delete(f"{key_puntos}:{punto}:desc") 

        # Eliminar el conjunto de puntos
        redis.delete(key_puntos)

        # Borrar ruta activa y posición pública del conductor
        redis.delete(f"conductor:{id_conductor}:ruta")
        redis.zrem("conductor:posiciones", id_conductor)

    return '', 204



# Enviar ubicación
@app.route('/api/conductor/posicion', methods=['POST'])
def registrar_posicion():
    id_conductor = session['usuario']['_id']
    data = request.get_json()
    lat, lng = data['lat'], data['lng']

    # Registrar la ubicación públicamente
    redis.geoadd("conductor:posiciones", (lng, lat, id_conductor))

    ruta_id = redis.get(f"conductor:{id_conductor}:ruta")
    visitados = []
    ruta_finalizada = False

    if ruta_id:
        # Clave específica del conjunto de puntos del conductor
        key_ruta = f"ruta:{ruta_id}:conductor:{id_conductor}:puntos"
        cercanos = redis.georadius(key_ruta, lng, lat, 50, unit='m')

        if cercanos:
            for cercano in cercanos:
                redis.delete(f"{key_ruta}:{cercano}:desc")  

            redis.zrem(key_ruta, *cercanos)
            visitados = list(cercanos)

            if redis.zcard(key_ruta) == 0:
                # Ruta finalizada
                redis.delete(f"conductor:{id_conductor}:ruta")
                redis.delete(key_ruta)
                redis.zrem("conductor:posiciones", id_conductor)
                ruta_finalizada = True

    return jsonify({
        'visitados': visitados,
        'ruta_finalizada': ruta_finalizada
    })



# -----------Monitoreo de Trafico----------------
@app.route('/api/rutas_activas')
def rutas_activas():
    rutas = mongo['rutas'].find({}, {'nombre': 1})
    return jsonify([{
        '_id': str(r['_id']),
        'nombre': r['nombre']
    } for r in rutas])

# @app.route('/api/rutas_activas')
# def rutas_activas():
#     from collections import defaultdict

#     conteo_rutas = defaultdict(int)

#     # Recorremos todas las rutas activas en Redis
#     for key in redis.scan_iter("conductor:*:ruta"):
#         ruta_id = redis.get(key)
#         if ruta_id:
#             conteo_rutas[str(ruta_id)] += 1

#     rutas_ids = list(conteo_rutas.keys())
#     rutas = mongo['rutas'].find({"_id": {"$in": [ObjectId(rid) for rid in rutas_ids]}}, {"nombre": 1})

#     resultado = []
#     for r in rutas:
#         _id = str(r['_id'])
#         resultado.append({
#             "_id": _id,
#             "nombre": f"{r['nombre']} ({conteo_rutas[_id]} activo{'s' if conteo_rutas[_id] > 1 else ''})"
#         })

#     return jsonify(resultado)


@app.route('/api/monitoreo')
def monitoreo_rutas_y_conductores():
    data = []

    # caches temporales
    cache_conductores = {}
    cache_usuarios = {}
    cache_rutas = {}

    for key in redis.scan_iter("conductor:*:ruta"):
        id_usuario = key.split(":")[1]
        ruta_id = redis.get(key)
        if not ruta_id:
            continue

        # conductor desde cache o Mongo
        if id_usuario in cache_conductores:
            conductor_doc = cache_conductores[id_usuario]
        else:
            conductor_doc = mongo['conductores'].find_one({"usuario_id": ObjectId(id_usuario)})
            if not conductor_doc:
                continue
            cache_conductores[id_usuario] = conductor_doc

        # usuario desde cache o Mongo
        if id_usuario in cache_usuarios:
            usuario_doc = cache_usuarios[id_usuario]
        else:
            usuario_doc = mongo['usuarios'].find_one({"_id": ObjectId(id_usuario)})
            if not usuario_doc:
                continue
            cache_usuarios[id_usuario] = usuario_doc

        nombre = usuario_doc.get("nombre", "")
        placa = conductor_doc.get("vehiculo", {}).get("placa", "")

        # ruta desde cache o Mongo
        if ruta_id in cache_rutas:
            nombre_ruta = cache_rutas[ruta_id]
        else:
            ruta_doc = mongo['rutas'].find_one({"_id": ObjectId(ruta_id)})
            nombre_ruta = ruta_doc['nombre'] if ruta_doc else "Sin nombre"
            cache_rutas[ruta_id] = nombre_ruta

        # posición del conductor
        pos = redis.geopos("conductor:posiciones", id_usuario)
        if not pos or pos[0] is None:
            continue

        # puntos de ruta en Redis
        puntos_key = f"ruta:{ruta_id}:conductor:{id_usuario}:puntos"
        puntos_ids = redis.zrange(puntos_key, 0, -1)
        puntos = []

        if puntos_ids:
            coords = redis.geopos(puntos_key, *puntos_ids)
            descs = redis.mget([f"{puntos_key}:{pid}:desc" for pid in puntos_ids])

            for pid, coord, desc in zip(puntos_ids, coords, descs):
                if coord:
                    puntos.append({
                        "id": pid,
                        "lat": coord[1],
                        "lng": coord[0],
                        "desc": desc or ""
                    })

        data.append({
            "conductor": id_usuario,
            "nombre": nombre,
            "placa": placa,
            "ruta_nombre": nombre_ruta,
            "posicion": {
                "lat": pos[0][1],
                "lng": pos[0][0]
            },
            "puntos": puntos
        })

    return jsonify(data)

# ----------------------- filtro rutas ----------------------
@app.route('/api/filtro_por_ruta')
def filtro_por_ruta():
    id_ruta = request.args.get('id')

    if not id_ruta:
        return jsonify({'conductores': []})

    # Buscar todos los conductores activos con esa ruta
    ids_conductores = []

    for key in redis.scan_iter("conductor:*:ruta"):
        id_usuario = key.split(":")[1]
        ruta_activa = redis.get(key)

        if ruta_activa == id_ruta:
            ids_conductores.append(id_usuario)

    return jsonify({'conductores': ids_conductores})


# ------------filtro por placa----------------------
@app.route('/api/filtro_por_placa')
def filtro_por_placa():
    placa = request.args.get('placa')
    if not placa:
        return jsonify({'error': 'Placa no proporcionada'}), 400

    placa = placa.strip().upper()
    conductor = mongo['conductores'].find_one({"vehiculo.placa": placa})    
    if not conductor:
        return jsonify({'error': 'Conductor no encontrado'}), 404

    usuario_id = str(conductor['usuario_id'])

    if not redis.exists(f"conductor:{usuario_id}:ruta"):
        return jsonify({'error': 'Conductor no está en ruta activa'}), 404

    return jsonify({'conductor': usuario_id})

# ---------------------- MAIN ----------------------

if __name__ == '__main__':
    app.run(port=1000, debug=True)
