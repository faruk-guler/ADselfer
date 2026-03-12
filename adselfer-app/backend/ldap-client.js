const ldap = require('ldapjs');
require('dotenv').config({ path: './config/.env' });

const createClient = () => {
    return ldap.createClient({
        url: process.env.AD_URL,
        tlsOptions: { rejectUnauthorized: false } // Change to true if using CA certs
    });
};

const searchUser = (client, username) => {
    return new Promise((resolve, reject) => {
        const opts = {
            filter: `(sAMAccountName=${username})`,
            scope: 'sub',
            attributes: ['dn', 'mail', 'displayName', 'description'] // 'description' used for security questions as example
        };

        client.search(process.env.AD_BASE_DN, opts, (err, res) => {
            if (err) return reject(err);

            let user = null;
            res.on('searchEntry', (entry) => {
                user = entry.object;
            });

            res.on('error', (err) => {
                reject(err);
            });

            res.on('end', (result) => {
                if (result.status !== 0) return reject(new Error('LDAP Search Failed'));
                resolve(user);
            });
        });
    });
};

const bindUser = (dn, password) => {
    const client = createClient();
    return new Promise((resolve, reject) => {
        client.bind(dn, password, (err) => {
            if (err) {
                client.unbind();
                return reject(err);
            }
            resolve(client);
        });
    });
};

module.exports = { createClient, searchUser, bindUser };
