import express from 'express';
import { Client } from 'pg';
import FlakeId from 'flake-idgen';
const intformat = require('biguint-format');
import { Member, Role } from '../interfaces';

export default (websockets: Map<string, WebSocket[]>, app: express.Application, database: Client, flake: FlakeId) => {
    app.get('/guilds/*', (req: express.Request, res: express.Response) => {
        const urlParamsValues: string[] = Object.values(req.params);
        const guildId = urlParamsValues
            .map((x) => x.replace(/\//g, ''))
            .filter((x) => {
                return x != '';
            })[0];
        if (guildId) {
            database.query(`SELECT * FROM guilds`, (err, dbRes) => {
                if (!err) {
                    const guild = dbRes.rows.find(x => x?.id === guildId);
                    if (guild) {
                        if (JSON.parse(guild.members).find((x: Member) => x?.id === res.locals.user)) {
                            res.send(Object.keys(guild).filter(x => x !== 'invites' && x !== 'channels' && x !== 'bans').reduce((obj, key, index) => ({ ...obj, [key]: Object.keys(guild).filter(x => x !== 'invites' && x !== 'channels' && x !== 'bans').map(x => x === 'bans' || x === 'roles' ? JSON.parse(guild[x]) : x === 'members' ? Object.keys(JSON.parse(guild[x])).length : guild[x])[index] }), {}));
                        } else {
                            res.status(403).send({ error: "You aren't in this guild." });
                        }
                    } else {
                        res.status(404).send({ error: "Guild not found." });
                    }
                } else {
                    res.status(500).send({ error: "Something went wrong with our server." });
                }
            });
        } else {
            res.status(404).send({ error: "Not found." });
        }
    });

    app.post('/guilds', (req: express.Request, res: express.Response) => {
        if (req.body.name && req.body.name.length < 31) {
            const guild = {
                id: intformat(flake.next(), 'dec').toString(),
                name: req.body.name,
                description: req.body.description ?? null,
                public: false,
                channels: [{ id: intformat(flake.next(), 'dec').toString(), name: 'general', topic: null, creation: Date.now(), roles: [{ id: '0', permissions: 456 }, { id: '1', permissions: 192 }], messages: [], pins: [] }],
                roles: [{ id: '0', name: 'Owner', permissions: 3647, color: null, hoist: false }, { id: '1', name: 'Members', permissions: 513, color: null, hoist: false }],
                members: [{ id: res.locals.user, nickname: null, roles: ['0', '1'] }],
                creation: Date.now(),
                bans: [],
                invites: []
            }
            database.query(`INSERT INTO guilds (id, name, description, public, channels, roles, members, bans, invites) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [guild.id, guild.name, guild.description, guild.public, JSON.stringify(guild.channels), JSON.stringify(guild.roles), JSON.stringify(guild.members), JSON.stringify(guild.bans), JSON.stringify(guild.invites)], (err, dbRes) => {
                if (!err) {
                    websockets.get(res.locals.user)?.forEach(websocket => {
                        websocket.send(JSON.stringify({ event: 'guildJoined', guild: guild }));
                    });
                    res.send(guild);
                } else {
                    console.log(err);
                    res.status(500).send({ error: "Something went wrong with our server." });
                }
            });
        } else {
            res.status(400).send({ error: "Something is missing." });
        }
    });

    app.patch('/guilds/*', (req: express.Request, res: express.Response) => {
        const urlParamsValues: string[] = Object.values(req.params);
        const guildId = urlParamsValues
            .map((x) => x.replace(/\//g, ''))
            .filter((x) => {
                return x != '';
            })[0];
        if (guildId) {
            database.query(`SELECT * FROM guilds`, (err, dbRes) => {
                if (!err) {
                    const guild = dbRes.rows.find(x => x?.id === guildId);
                    if (guild) {
                        const members = JSON.parse(guild.members);
                        Object.keys(guild).reduce((obj, key, index) => ({ ...obj, [key]: Object.keys(guild).map(x => x === 'channels' || x === 'members' || x === 'roles' || x === 'invites' ? JSON.parse(guild[x]) : guild[x])[index] }), {});
                        if (members.find((x: Member) => x?.id === res.locals.user)?.roles.find((x: string) => ((guild.roles.find((y: Role) => y?.id === x)?.permissions ?? 0) & 0x0000000010) === 0x0000000010)) {
                            let changesWereMade = false;

                            if (req.body.name && req.body.name.length < 31) {
                                guild.name = req.body.name;
                                changesWereMade = true;
                            }

                            if (req.body.description && req.body.description.length < 1025) {
                                guild.description = req.body.description;
                                changesWereMade = true;
                            }

                            if (typeof req.body.public === 'boolean') {
                                guild.public = req.body.public;
                                changesWereMade = true;
                            }

                            if (req.body.owner && members.find((x: Member) => x?.id === res.locals.user)?.roles.includes('0') && members.find((x: Member) => x?.id === req.body.owner)) {
                                members[members.findIndex((x: Member) => x?.id === res.locals.user)].roles.splice(members[members.findIndex((x: Member) => x?.id === res.locals.user)].roles.indexOf('0'), 1);
                                members[members.findIndex((x: Member) => x?.id === req.body.owner)].roles.push('0');
                                changesWereMade = true;
                            }

                            database.query(`UPDATE guilds SET name = $1, members = $2 WHERE id = $3`, [guild.name, JSON.stringify(members), guildId], (err, dbRes) => {
                                if (!err) {
                                    if (changesWereMade) {
                                       members.forEach((member: Member) => {
                                            websockets.get(member.id)?.forEach(websocket => {
                                                websocket.send(JSON.stringify({ event: 'guildEdited', guild: guild }));
                                            });
                                        });
                                        res.send(guild);
                                    } else {
                                        res.status(400).send({ error: "Something is missing." });
                                    }
                                } else {
                                    res.status(500).send({ error: "Something went wrong with our server." });
                                }
                            });
                        } else {
                            res.status(403).send({ error: "Missing permission." });
                        }
                    } else {
                        res.status(404).send({ error: "Guild not found." });
                    }
                } else {
                    res.status(500).send({ error: "Something went wrong with our server." });
                }
            });
        } else {
            res.status(400).send({ error: "Something is missing." });
        }
    });

    app.delete('/guilds/*', (req: express.Request, res: express.Response) => {
        const urlParamsValues: string[] = Object.values(req.params);
        const guildId = urlParamsValues
            .map((x) => x.replace(/\//g, ''))
            .filter((x) => {
                return x != '';
            })[0];
        if (guildId) {
            database.query(`SELECT * FROM guilds`, (err, dbRes) => {
                if (!err) {
                    const guild = dbRes.rows.find(x => x?.id === guildId);
                    if (guild) {
                        const members = JSON.parse(guild.members);
                        if (members.find((x: Member) => x?.id === res.locals.user)?.roles.includes('0')) {
                            const parsedGuild = Object.keys(guild).filter(x => x !== 'invites' && x !== 'channels' && x !== 'bans').reduce((obj, key, index) => ({ ...obj, [key]: Object.keys(guild).filter(x => x !== 'invites' && x !== 'channels' && x !== 'bans').map(x => x === 'bans' || x === 'roles' ? JSON.parse(guild[x]) : x === 'members' ? Object.keys(JSON.parse(guild[x])).length : guild[x])[index] }), {});
                    
                            database.query(`DELETE FROM guilds WHERE id = $1`, [guildId], async (err, dbRes) => {
                                if (!err) {
                                    members.forEach((member: Member) => {
                                        websockets.get(member.id)?.forEach(websocket => {
                                            websocket.send(JSON.stringify({ event: 'guildDeleted', guild: guild }));
                                        });
                                    });
                                    res.send(parsedGuild);
                                } else {
                                    res.status(500).send({ error: "Something went wrong with our server." });
                                }
                            });
                        } else {
                            res.status(403).send({ error: "You don't own this guild." });
                        }
                    } else {
                        res.status(404).send({ error: "Guild not found." });
                    }
                } else {
                    res.status(500).send({ error: "Something went wrong with our server." });
                }
            });
        } else {
            res.status(400).send({ error: "Something is missing." });
        }
    });
};