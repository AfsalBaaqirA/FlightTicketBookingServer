import os
import random
import string
import uuid
from bcrypt import gensalt, hashpw, checkpw
from dotenv import load_dotenv
import pymongo
from flask import jsonify, request

load_dotenv()

MONGO_DB_URL = os.getenv('MONGO_DB_URL')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME')

mongo_client = pymongo.MongoClient(MONGO_DB_URL)
mongo_db = mongo_client.get_database(MONGO_DB_NAME)
users = mongo_db.get_collection('users')
flights = mongo_db.get_collection('flights')
sessions = mongo_db.get_collection('sessions')
print("MongoDB connected")
mongo_db.command('ping')


def api_endpoints(app):
    @app.route('/api/test', methods=['GET'])
    def test():
        return 'Hello World!'

    @app.route('/api/auth/signup', methods=['POST'])
    def signUp():
        try:
            data = request.get_json()
            firstName = data.get('firstName')
            lastName = data.get('lastName')
            password = data.get('password')
            email = data.get('email')
            hashed_password = hashpw(password.encode('utf-8'), gensalt())
            query = {
                'email': email,
            }
            user = users.find_one(query)
            if user:
                response = {
                    'status': '400',
                    'message': 'Email already exists'
                }
            else:
                users.insert_one({'firstName': firstName, 'lastName': lastName,
                                 'password': hashed_password, 'email': email, 'bookings': []})
                response = {
                    'status': '200',
                    'message': 'Account created successfully'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})

    @app.route('/api/auth/signin', methods=['POST'])
    def signIn():
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            token = ''
            query = {
                'email': email,
            }
            user = users.find_one(query)
            if user:
                if checkpw(password.encode('utf-8'), user['password']):
                    session = sessions.find_one(query)
                    if session:
                        token = uuid.uuid4().hex
                        sessions.update_one(
                            query, {'$set': {'sessionToken': token}})
                    else:
                        token = uuid.uuid4().hex
                        sessions.insert_one(
                            {'sessionToken': token, 'email': email})
                    role = user['role'] if 'role' in user else 'user'
                    response = {
                        'status': '200',
                        'message': 'Login successful',
                        'token': token,
                        'role': role
                    }
                else:
                    response = {
                        'status': '400',
                        'message': 'Invalid password'
                    }
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid email'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})

    @app.route('/api/auth/signout', methods=['POST'])
    def signOut():
        try:
            data = request.get_json()
            token = data.get('token')
            query = {
                'sessionToken': token,
            }
            session = sessions.find_one(query)
            if session:
                sessions.delete_one(query)
                response = {
                    'status': '200',
                    'message': 'Logout successful'
                }
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid token'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})

    @app.route('/api/auth/validate', methods=['POST'])
    def validate():
        try:
            token = request.get_json().get('token')
            query = {
                'sessionToken': token,
            }
            session = sessions.find_one(query)
            if session:
                query = {
                    'email': session['email'],
                }
                user = users.find_one(query)
                if user:
                    role = user['role'] if 'role' in user else 'user'
                    response = {
                        'status': '200',
                        'message': 'Valid token',
                        'role': role
                    }
                else:
                    response = {
                        'status': '400',
                        'message': 'Invalid token'
                    }
                
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid token'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        print(response)
        return jsonify({'response': response})
    

    @app.route('/api/flights/add/<token>', methods=['POST'])
    def addFlight(token):
        try:
            session_query = {
                'sessionToken': token,
            }
            session = sessions.find_one(session_query)
            if session:
                user_query = {
                    'email': session['email'],
                }
                user = users.find_one(user_query)
                if user:
                    if user['role'] == 'admin':
                        flightData = request.get_json()
                        query = {
                            'flightNumber': flightData['flightNumber'],
                        }
                        flight = flights.find_one(query)
                        if flight:
                            response = {
                                'status': '400',
                                'message': 'Flight already exists'
                            }
                        else:
                            flights.insert_one(flightData)
                            response = {
                                'status': '200',
                                'message': 'Flight added successfully'
                            }
                    else:
                        response = {
                            'status': '400',
                            'message': 'UnAuthorized User'
                        }
                else:
                    response = {
                        'status': '400',
                        'message': 'Invalid user'
                    }
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid token'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})
    
    @app.route('/api/flights/remove/<token>/<flightNumber>', methods=['DELETE'])
    def removeFlight(token, flightNumber):
        try:
            session_query = {
                'sessionToken': token,
            }
            session = sessions.find_one(session_query)
            if session:
                user_query = {
                    'email': session['email'],
                }
                user = users.find_one(user_query)
                if user:
                    if user['role'] == 'admin':
                        query = {
                            'flightNumber': flightNumber,
                        }
                        flight = flights.find_one(query)
                        if flight:
                            flights.delete_one(query)
                            response = {
                                'status': '200',
                                'message': 'Flight removed successfully'
                            }
                        else:
                            response = {
                                'status': '400',
                                'message': 'Flight does not exist'
                            }
                    else:
                        response = {
                            'status': '400',
                            'message': 'UnAuthorized User'
                        }
                else:
                    response = {
                        'status': '400',
                        'message': 'Invalid user'
                    }
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid token'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})
    
    @app.route('/api/flights/<token>', methods=['GET'])
    def getFlights(token):
        try:
            session_query = {
                'sessionToken': token,
            }
            session = sessions.find_one(session_query)
            if session:
                user_query = {
                    'email': session['email'],
                }
                user = users.find_one(user_query)
                if user:
                    if user['role'] == 'admin':
                        projection = {
                            '_id': 0
                        }
                        flights_list = list(flights.find({}, projection))
                        response = {
                            'status': '200',
                            'message': 'Flights retrieved successfully',
                            'flights': flights_list
                        }
                    else:
                        response = {
                            'status': '400',
                            'message': 'UnAuthorized User'
                        }
                else:
                    response = {
                        'status': '400',
                        'message': 'Invalid user'
                    }
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid token'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})
    

    @app.route('/api/flights/search', methods=['POST'])
    def searchFlights():
        try:
            data = request.get_json()
            query = {
                "from": data['from'],
                "to": data['to'],
                "date": data['date'],
                "seatCount": {
                    "$gte": int(data['passengers'])
                }
            }
            print(query)
            projection = {
                '_id': 0,
                'passengers': 0
            }
            flights_list = list(flights.find(query, projection))
            response = {
                'status': '200',
                'message': 'Flights retrieved successfully',
                'flights': flights_list
            }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})

    @app.route('/api/flight/<flightNumber>', methods=['GET'])
    def getFlight(flightNumber):
        try:
            query = {
                "flightNumber": flightNumber,
            }
            projection = {
                '_id': 0,
                'passengers': 0
            }
            flight = flights.find_one(query, projection)
            response = {
                'status': '200',
                'message': 'Flight retrieved successfully',
                'flight': flight
            }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})

    @app.route('/api/flight/book/<token>', methods=['POST'])
    def bookFlight(token):
        try:
            data = request.get_json()
            print(data)
            passengers = list(data.get('passengers'))
            query = {
                'sessionToken': token,
            }
            session = sessions.find_one(query)
            if session:
                email = session['email']
                query = {
                    'email': email,
                }
                user = users.find_one(query)
                if user:
                    flight = flights.find_one(
                        {'flightNumber': data['flightNumber']})
                    if flight:
                        flight['seatCount'] = flight['seatCount'] - len(passengers)
                        flights.update_one({'flightNumber': data['flightNumber']}, {'$set': {'seatCount': flight['seatCount']}})
                        flights.update_one({"flightNumber": data['flightNumber']}, {"$push": {"passengers": passengers}})
                        ticketPrice = data.get('ticketPrice')
                        ticketNumber = ''.join(random.choices(
                            string.ascii_uppercase + string.digits, k=8))
                        booking = {
                            'ticketNumber': ticketNumber,
                            'flightNumber': data['flightNumber'],
                            'from': flight['from'],
                            'to': flight['to'],
                            'date': flight['date'],
                            'time': flight['time'],
                            'passengers': data['passengers'],
                            'ticketPrice': ticketPrice
                        }
                        bookings = user['bookings']
                        bookings.append(booking)
                        users.update_one(
                            query, {'$set': {'bookings': bookings}})
                        response = {
                            'status': '200',
                            'message': 'Flight booked successfully',
                            'booking': booking
                        }
                    else:
                        response = {
                            'status': '400',
                            'message': 'Invalid flight number'
                        }
                else:
                    response = {
                        'status': '400',
                        'message': 'Invalid email'
                    }
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid token'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})

    @app.route('/api/flight/myBookings/<token>', methods=['GET'])
    def getMyBookings(token):
        try:
            query = {
                'sessionToken': token,
            }
            session = sessions.find_one(query)
            if session:
                email = session['email']
                query = {
                    'email': email,
                }
                user = users.find_one(query)
                if user:
                    response = {
                        'status': '200',
                        'message': 'Bookings retrieved successfully',
                        'bookings': user['bookings']
                    }
                else:
                    response = {
                        'status': '400',
                        'message': 'Invalid email'
                    }
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid token'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})
    
    @app.route('/api/flight/cancelTicket/<token>/<ticketNumber>', methods=['DELETE'])
    def cancelTicket(token, ticketNumber):
        try:
            query = {
                'sessionToken': token,
            }
            session = sessions.find_one(query)
            if session:
                email = session['email']
                query = {
                    'email': email,
                }
                user = users.find_one(query)
                if user:
                    bookings = user['bookings']
                    for booking in bookings:
                        if booking['ticketNumber'] == ticketNumber:
                            bookings.remove(booking)
                            flights.update_one({'flightNumber': booking['flightNumber']}, {'$pull': {'passengers': {'email': email}}})
                            flights.update_one({'flightNumber': booking['flightNumber']}, {'$inc': {'seatCount': len(booking['passengers'])}})
                            users.update_one(query, {'$set': {'bookings': bookings}})
                            response = {
                                'status': '200',
                                'message': 'Ticket cancelled successfully',
                                'booking': booking
                            }
                            break
                    else:
                        response = {
                            'status': '400',
                            'message': 'Invalid ticket number'
                        }
                else:
                    response = {
                        'status': '400',
                        'message': 'Invalid email'
                    }
            else:
                response = {
                    'status': '400',
                    'message': 'Invalid token'
                }
        except Exception as e:
            response = {
                'status': '400',
                'message': str(e)
            }
        return jsonify({'response': response})
