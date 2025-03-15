import express from 'express';
import passport from 'passport';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JWTStrategy, ExtractJwt } from 'passport-jwt';

const ERR_MSG = 'Incorrect username or password'
const SECRET_KEY = 'secret_key' // лучше в .env файлах такое хранить, но для удобства пусть будет тут

const mockUser = {
    id: '1',
    username: 'user',
    passwordHash: bcrypt.hashSync('password', 10),
};

passport.use(new LocalStrategy(
    (username, password, done) => {
        if (username !== mockUser.username) {
            return done(null, false, { message: ERR_MSG });
        }

        const isValid = bcrypt.compare(password, mockUser.passwordHash);
        if (!isValid) {
            return done(null, false, { message: ERR_MSG });
        }

        return done(null, mockUser);
    }
));

const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: SECRET_KEY,
};

passport.use(new JWTStrategy(
    jwtOptions,
    (jwtPayload, done) => {
    if (jwtPayload.id !== mockUser.id) {
        return done(null, false);
    }
    return done(null, mockUser);
}));

const app = express();
app.use(express.json());
app.use(passport.initialize());

app.post('/login', (req, res, next) => {
    passport.authenticate('local', { session: false }, (err: any, user: { id: any; }, info: { message: any; }) => {
        if (err || !user) {
            return res.status(401).json({ message: info?.message || 'Auth error' });
        }

        const token = jwt.sign(
            { id: user.id },
            jwtOptions.secretOrKey,
            { expiresIn: '1h' }
        );

        return res.json({ token });
    })(req, res, next);
});

app.get('/profile',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
        res.json({
            message: 'Successfully logged in',
            user: req.user,
        });
    }
);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});