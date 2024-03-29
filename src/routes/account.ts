import { Info, User } from '../interfaces';

import express from "express";
    import argon2 from 'argon2';
    import { SignJWT } from 'jose/jwt/sign';
    import { importPKCS8 } from 'jose/key/import';
import { Client } from 'pg';
import FlakeId from 'flake-idgen';
const intformat = require('biguint-format');
import crypto from 'crypto';

export default (websockets: Map<string, WebSocket[]>, app: express.Application, database: Client, flake: FlakeId, email: any, checkLogin: any, clientDomain: string) => {
    app.post('/login', (req: express.Request, res: express.Response) => {
        database.query(`SELECT * FROM users`, async (err, dbRes) => {
            if (!err) {
                const user = dbRes.rows.find(x => x.email === req.body.email);
                if (user) {
                    try {
                        if (await argon2.verify(user.password, req.body.password, { type: argon2.argon2id })) {
                            if(user.verified) {
                            const correct = (await checkLogin(user.token)).id !== '';
                            if(!correct) {
                            const token = 'Bearer ' +  await generateToken({ id: user.id });
                            database.query('UPDATE users SET token = $1 WHERE id = $2', [token, user.id], err => {
                                if (!err) {
                                    res.send({ token: token });
                                } else {
                                    res.status(500).send({ error: "Something went wrong with our server." });
                                }
                            });
                        } else {
                            res.send({ token: user.token });
                        }
                    } else {
                        res.status(403).send({ error: "Account not verified." });
                    }
                        } else {
                            res.status(401).send({ error: "Invalid information." });
                        }
                    } catch(e) {
                        res.status(500).send({ error: "Something went wrong with our server." });
                    }
                } else {
                    res.status(401).send({ error: "Invalid information." });
                }
            } else {
                res.status(500).send({ error: "Something went wrong with our server." });
            }
        });
    });

    app.post('/register', (req: express.Request, res: express.Response) => {
        if (/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(req.body.email) && req.body.username && req.body.username.length < 31 && req.body.password) {
        database.query(`SELECT * FROM users`, async (err, dbRes) => {
                if (!err) {
                    const badAccount = dbRes.rows.find(x => x.email === req.body.email);
                    if (!badAccount?.verified) {
                        let canContinue = false;

                        if(badAccount) {
                            database.query('DELETE FROM users WHERE id = $1', [badAccount.id], async (err, dbRes) => {
                                if (!err) {
                                    canContinue = true;
                                }
                            });
                        } else {
                            canContinue = true;
                        }

                        const id = intformat(flake.next(), 'dec').toString();
                        const password = await argon2.hash(req.body.password, { type: argon2.argon2id });
                        const token = 'Bearer ' +  await generateToken({ id: id });
                        const discriminator = generateDiscriminator(dbRes.rows.filter(x => x.username === req.body.username).map(x => x.discriminator) ?? []);
                        const verificator = Buffer.from(crypto.randomUUID()).toString('base64url');
                        database.query(`INSERT INTO users (id, token, email, password, username, discriminator, creation, verified, verificator) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [id, token, req.body.email, password, req.body.username, discriminator, Date.now(), false, verificator], (err, dbRes) => {
                            if (!err) {
                                email.sendMessage(Buffer.from(['MIME-Version: 1.0\n',
                                'Subject: Verify your Seltorn account!\n',
                                'From: seltornteam@gmail.com\n',
                                'To: ' + req.body.email + '\n\n',
                                'Thank you for registering to Seltorn!\n',
                                'To start using it, we need to verify your email address.\n',
                                'Click here to verify: ' + clientDomain +'/verify/' + verificator + '\n\n'].join('')).toString('base64url'));
                                res.send({});
                            } else {
                                res.status(500).send({ error: "Something went wrong with our server." });
                            }
                        });
                    } else {
                        res.status(401).send({ error: "Email in use." });
                    }
                } else {
                    res.status(500).send({ error: "Something went wrong with our server." });
                }
            });

        } else {
            res.status(400).send({ error: "Something is missing." });
        }
    });

    function generateDiscriminator(excluded: string[]): string {
        const pre = Math.floor(Math.random() * (9999 - 1 + 1) + 1);
        const final = pre.toString().padStart(4, '0');
        if (excluded.includes(final)) {
            return generateDiscriminator(excluded);
        } else {
            return final;
        }
    }

    async function generateToken(info: Info) {
        const privateKey = await importPKCS8(require('fs').readFileSync(__dirname + '/../../private.key').toString(), 'ES256');
        return await new SignJWT({ info })
            .setProtectedHeader({ alg: 'ES256' })
            .setIssuedAt()
            .setIssuer('seltorn')
            .setAudience('seltorn')
            .setExpirationTime('7d')
            .sign(privateKey);
    }
};