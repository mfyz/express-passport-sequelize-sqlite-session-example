const express = require('express')
const bodyParser = require('body-parser')
const pug = require('pug')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const csurf = require('csurf')
const helmet = require('helmet')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const db = require('./db')(session)

const PORT = process.env.PORT || 4008

// express app
const app = express()
app.set('view engine', 'pug')
app.use(cookieParser())
app.use(express.static('public'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(session({
	secret: 'awesome auth',
	store: db.SessionStore,
	resave: false,
	saveUninitialized: true
}))

// security
const csrf = csurf({ cookie: true })
app.use(helmet())
app.use(csrf)
app.use(function (err, req, res, next) {
	if (err.code !== 'EBADCSRFTOKEN') return next(err)
	res.status(403).render('error', { message: 'Invalid form submission!' })
})

// passport
app.use(passport.initialize())
app.use(passport.session())
const passportConfig = { failureRedirect: '/login' }

const authRequired = (req, res, next) => {
	if (req.user) return next()
	else res.redirect('/login?required=1')
}

app.use((req, res, next) => {
	res.locals.user = req.user
	next()
})

passport.use(new LocalStrategy((username, password, done) => {
	db.getUserByUsername(username)
		.then(async (user) => {
			if (!user) return done('User not found!', false)
			if (!(await db.isPasswordHashVerified(user.password_hash, password))) return done('Invalid Password', false)
			return done(null, user)
		})
		.catch((err) => {
			return done(err)
		})
}))

passport.serializeUser((user, cb) => {
	cb(null, user.uid)
})

passport.deserializeUser((uid, cb) => {
	db.getUserById(uid)
		.then((user) => {
			cb(null, user)
		})
		.catch((err) => {
			cb(err, null)
		})
})

// App start

app.listen(PORT, () => console.log(`App listening on port ${PORT}!`))

/* Routes */

app.get('/', (req, res) => {
	res.render('index')
})

app.get('/member', authRequired, (req, res) => {
	res.render('member')
})

app.all('/login', (req, res, next) => {
	new Promise((resolve, reject) => {
		if (Object.keys(req.body).length > 0) {
			passport.authenticate('local', (err, user, info) => {
				if (err) {
					reject(err)
				}
				else if (user) {
					resolve(user)
				}
			})(req, res, next)
		}
		else {
			reject()
		}
	})
		.then(user => new Promise((resolve, reject) => {
			req.login(user, err => { // save authentication
				if (err) return reject(err)
				console.log('auth completed - redirecting to member area')
				return res.redirect('/member')
			})
		}))
		.catch(errorMsg => {
			let error = errorMsg
			if (!error && req.query.required) error = 'Authentication required'

			res.render('login', {
				csrfToken: req.csrfToken(),
				error,
				form: req.body,
			})
		})
})

app.all('/register', (req, res) => {
	new Promise(async (resolve, reject) => {
		if (Object.keys(req.body).length > 0) {
			// console.log(req.body)
			if (
				!(req.body.email && req.body.email.length > 5)
				|| !(req.body.username && req.body.username.length > 1)
				|| !(req.body.password && req.body.password.length > 3)
				|| !(req.body.password2 && req.body.password2.length > 3)
			) {
				reject('Please fill all fields')
			}
			else if (!(
				req.body.email.indexOf('@') !== -1 
				&& req.body.email.indexOf('.') !== -1
			)) {
				reject('Invalid email address')
			}
			else if (req.body.password !== req.body.password2) {
				reject("Password don't match")
			}
			else if (await db.isUsernameInUse(req.body.username)) {
				reject('Username is taken')
			}
			else if (await db.isEmailInUse(req.body.email)) {
				reject('Email address is already registered')
			}
			else {
				resolve(true)
			}
		}
		else {
			resolve(false)
		}
	})
		.then(isValidFormData => new Promise((resolve, reject) => {
			if (Object.keys(req.body).length > 0 && isValidFormData) {
				db.createUserRecord({
					username: req.body.username,
					email: req.body.email,
					password: req.body.password
				})
					.then((createdUser) => {
						// console.log('====> user created...')
						// console.log(creationSuccessful)
						// authenticate?
						resolve(createdUser)
					})
					.catch(err => reject(err))
			}
			else {
				resolve(false)
			}
		}))
		.then((createdUserRecord) => {
			if (createdUserRecord) {
				// Log them in in the session
				req.login(createdUserRecord, (err) => {
					console.log(err)
				})
				res.render('register-success')
			}
			else {
				res.render('register', {
					csrfToken: req.csrfToken(),
					form: req.body
				})
			}
		})
		.catch((error) => {
			// console.log(error)
			res.render('register', {
				csrfToken: req.csrfToken(),
				error,
				form: req.body
			})
		})
})

app.get('/logout', authRequired, (req, res) => {
	req.logout()
	res.redirect('/')
})