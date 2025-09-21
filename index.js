'use strict';
const { readFileSync } = require('fs');
const { Server } = require('ssh2');
const ldap = require('ldapjs');
const axios = require('axios');
const config = require('./config');
const fs = require('fs');
const { execSync } = require('child_process');
const nodemailer = require('nodemailer');
const path = require('path');

const users = [];

const LDAP_CONFIG = config.ldap;
const AUTHENTIK_CONFIG = config.authentik;
const transporter = nodemailer.createTransport(config.smtp);
const codesFilePath = path.join(__dirname, 'codes.json');

const locales = {};
const localeFiles = ['en', 'fr'];
localeFiles.forEach(lang => {
  try {
    locales[lang] = JSON.parse(fs.readFileSync(path.join(__dirname, 'locales', `${lang}.json`), 'utf8'));
  } catch (err) {
    console.error(`Failed to load locale ${lang}:`, err.message);
  }
});

function getText(key, lang = 'en') {
  return (locales[lang] && locales[lang][key]) || (locales['en'] && locales['en'][key]) || key;
}

function getUserLang(user) {
  return user?.attributes?.language || 'en';
}

function getAvailableShells() {
  try {
    const shellPath = "/etc/shells";
    const shellFile = fs
      .readFileSync(shellPath, "utf8")
      .split("\n")
      .filter((line) => !/^\s*#/.test(line));

    const uniqueShells = shellFile
      .map((line) => line.trim())
      .map((line) => line.replace(/^\s*\/.*\//, ""))
      .filter(
        (value, index, self) => self.indexOf(value) === index && value !== "",
      );

    const shells = uniqueShells.map(
      (shell) =>
        shellFile.find(
          (line) => line.includes(shell) && line.includes("/bin/"),
        ) || shellFile.find((line) => line.includes(shell)),
    ).filter(Boolean);

    return shells;
  } catch (error) {
    console.error('Error reading /etc/shells:', error.message);
    return ['/bin/bash', '/bin/sh', '/bin/zsh'];
  }
}

function getCurrentShell(username) {
  try {
    const output = execSync(`getent passwd ${username} | cut -d: -f7`, { encoding: 'utf8' }).trim();
    return output || '/bin/bash';
  } catch (error) {
    console.error('Error getting current shell:', error.message);
    return '/bin/bash';
  }
}

async function sendVerificationEmail(email, code) {
  try {
    await transporter.sendMail({
      from: config.smtp.from,
      to: email,
      subject: 'Nest Signup Verification',
      text: `Your verification code for Nest signup is: ${code}\n\nIf you didn't request this, please ignore this email.`
    });
  } catch (error) {
    console.error('Error sending email:', error.message);
    throw error;
  }
}

async function getAuthentikUser(username) {
  try {
    const response = await axios.get(`${AUTHENTIK_CONFIG.url}/api/v3/core/users/?username=${username}`, {
      headers: {
        'Authorization': `Bearer ${AUTHENTIK_CONFIG.token}`,
        'Content-Type': 'application/json'
      }
    });
    if (response.data.results && response.data.results.length > 0) {
      return response.data.results[0];
    }
    return null;
  } catch (error) {
    console.error('Error fetching user from Authentik:', error.message);
    return null;
  }
}

function searchByPublicKey(publicKey) {
  return new Promise(async (resolve, reject) => {
    const client = ldap.createClient({
      url: LDAP_CONFIG.url,
      tlsOptions: LDAP_CONFIG.tlsOptions,
      connectTimeout: 10000  // 10s timeout, identity can be slow at times :/
    });
    client.bind(LDAP_CONFIG.bindDN, LDAP_CONFIG.bindPassword, (err) => {
      if (err) {
        client.unbind();
        return reject(err);
      }
      const searchOptions = {
        scope: 'sub',
        filter: `(sshPublicKey=${publicKey}*)`
      };
      client.search(LDAP_CONFIG.baseDN, searchOptions, (err, res) => {
        if (err) {
          client.unbind();
          return reject(err);
        }
        let userInfo = null;
        res.on('searchEntry', (entry) => {
          userInfo = {};
          entry.attributes.forEach(attr => {
            userInfo[attr.type] = attr.values.length > 1 ? attr.values : attr.values[0];
          });
          userInfo.dn = String(entry.objectName || entry.dn);
        });
        res.on('error', (err) => {
          client.unbind();
          reject(err);
        });
        res.on('end', async () => {
          client.unbind();
          if (userInfo) {
            const authentikUser = await getAuthentikUser(userInfo.cn);
            if (authentikUser) {
              userInfo.pk = authentikUser.pk;
              userInfo.attributes = authentikUser.attributes || {};
            }
          }
          resolve(userInfo);
        });
      });
    });
  });
}

async function updateAuthentikAttribute(pk, attribute, value) {
  try {
    const currentResponse = await axios.get(`${AUTHENTIK_CONFIG.url}/api/v3/core/users/${pk}/`, {
      headers: {
        'Authorization': `Bearer ${AUTHENTIK_CONFIG.token}`,
        'Content-Type': 'application/json'
      }
    });
    const currentUser = currentResponse.data;
    let updateData = {};
    if (attribute === 'cn') {
      updateData.name = value;
    } else if (attribute === 'mail') {
      updateData.email = value;
    } else if (attribute === 'loginShell') {
      updateData.attributes = { ...currentUser.attributes, loginShell: value };
    } else {
      updateData.attributes = { ...currentUser.attributes, [attribute]: value };
    }
    const response = await axios.patch(`${AUTHENTIK_CONFIG.url}/api/v3/core/users/${pk}/`, updateData, {
      headers: {
        'Authorization': `Bearer ${AUTHENTIK_CONFIG.token}`,
        'Content-Type': 'application/json'
      }
    });
    return response.data;
  } catch (error) {
    throw new Error(`Failed to update ${attribute}: ${error.message}`);
  }
}

new Server({
  hostKeys: [readFileSync('host.key')],
}, (client) => {
  let stream;
  let authenticatedUser;
  let currentState = 'menu';
  let isSignup = false;
  let signupData = {};
  let verificationCode = null;
  let pendingEmail;

  function showDashboard() {
    const userLang = getUserLang(authenticatedUser);
    const currentShell = authenticatedUser.attributes?.loginShell || authenticatedUser.loginShell || getCurrentShell(authenticatedUser.username || authenticatedUser.cn);
    const sshKey = authenticatedUser.sshPublicKey || 'Not set';
    const isAdmin = authenticatedUser['ak-superuser'] === 'TRUE';
    const menuOptions = [
      '',
      getText('update_name', userLang),
      getText('update_email', userLang),
      getText('update_shell', userLang),
      getText('update_ssh_key', userLang),
      getText('change_password', userLang),
      getText('update_language', userLang),
    ];
    if (isAdmin) {
      menuOptions.push(getText('generate_signup_code', userLang));
      menuOptions.push(getText('list_signup_codes', userLang));
      menuOptions.push(getText('delete_signup_code', userLang));
    }
    menuOptions.push(getText('exit', userLang));
    const menuText = menuOptions.slice(1).map((opt, i) => `${i+1}. ${opt}`).join('\n');
    const info = `
                                          .MM.
                                          ;MM.
KKc.lONMMWXk;    ckXWMMWXk:   'xXWMMWXxoKKNMMXKKKK
MMXNo'.  .lWM0.oWNo'.  .,dWWldMW:.  .:XMN'dMM:....
MMW.       :MMWMN.        'MMMMWc.     .. cMM.
MMO        .MMMMWXXXXXXXXXXWWO,dKNMNKOd:. cMM.
MMO        .MMMMX                  .':OMMccMM.
MMO        .MMKNMO.      .kK0KKl      .MMk:MM;
MMO        .MMd.oXMKxoox0MXl ,OMNkdodkWWk. kWMKOOo
dd:        .dd;   ,xKNNKx,     .o0XNX0l.    .:oddc

${getText('welcome_back', userLang)}!

${getText('name_label', userLang)}: ${authenticatedUser.name || authenticatedUser.cn}
${getText('email_label', userLang)}: ${authenticatedUser.email || authenticatedUser.mail}
${getText('shell_label', userLang)}: ${currentShell}
${getText('ssh_key_label', userLang)}: ${sshKey.length > 50 ? sshKey.substring(0, 50) + '...' : sshKey}
${getText('username_label', userLang)}: ${authenticatedUser.username || authenticatedUser.cn}

${getText('menu', userLang)}:
${menuText}

${getText('choose_option', userLang)}: `;

    stream.write(info);
    currentState = 'menu';
  }

  function startSignup() {
    currentState = 'select_language';
    stream.write(`Select your language / Sélectionnez votre langue:\n1. English\n2. Français\nEnter number or code: `);
  }

  async function validateSignup() {
    try {
      const userCheck = await axios.get(`${AUTHENTIK_CONFIG.url}/api/v3/core/users/?username=${signupData.username}`, {
        headers: {
          'Authorization': `Bearer ${AUTHENTIK_CONFIG.token}`,
          'Content-Type': 'application/json'
        }
      });
      if (userCheck.data.results && userCheck.data.results.length > 0) {
        stream.write(getText('username_taken', signupData.language) + ': ');
        currentState = 'signup_username';
        return;
      }

      const emailCheck = await axios.get(`${AUTHENTIK_CONFIG.url}/api/v3/core/users/?email=${signupData.email}`, {
        headers: {
          'Authorization': `Bearer ${AUTHENTIK_CONFIG.token}`,
          'Content-Type': 'application/json'
        }
      });
      if (emailCheck.data.results && emailCheck.data.results.length > 0) {
        stream.write(getText('email_registered', signupData.language) + ': ');
        currentState = 'signup_email';
        return;
      }

      if (signupData.code) {
        verificationCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        await sendVerificationEmail(signupData.email, verificationCode);
        currentState = 'verify_code';
        stream.write(getText('verification_sent', signupData.language) + ': ');
      } else {
        const eligibilityResponse = await axios.get(`https://identity.hackclub.com/api/external/check?email=${signupData.email}`);
        const result = eligibilityResponse.data.result;
        if (result !== 'verified_eligible') {
          const message = getText(result, signupData.language) || `Unknown status: ${result}. Please visit identity.hackclub.com`;
          stream.write(`${message}\n`);
          stream.end(getText('signup_failed', signupData.language) + '\n');
          return;
        }

        verificationCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        await sendVerificationEmail(signupData.email, verificationCode);
        currentState = 'verify_code';
        stream.write(getText('verification_sent', signupData.language) + ': ');
      }
    } catch (error) {
      stream.write(`Signup validation failed: ${error.message}\n`);
      stream.end(getText('signup_failed', signupData.language) + '\n');
    }
  }

  async function createAccount() {
    const userData = {
      name: signupData.name,
      username: signupData.username,
      email: signupData.email,
      groups_by_name: ["c844feff-89b0-45cb-8204-8fc47afbd348"],
      is_active: false, // disable account for review
      attributes: {
        sshPublicKey: authenticatedUser.sshPublicKey,
        uid: signupData.username,
        language: signupData.language
      }
    };

    try {
      const response = await axios.post(`${AUTHENTIK_CONFIG.url}/api/v3/core/users/`, userData, {
        headers: {
          'Authorization': `Bearer ${AUTHENTIK_CONFIG.token}`,
          'Content-Type': 'application/json'
        }
      });
      const pk = response.data.pk;
      const password = Math.random().toString(36).substring(2, 14);

      await axios.post(`${AUTHENTIK_CONFIG.url}/api/v3/core/users/${pk}/set_password/`, {
        password
      }, {
        headers: {
          'Authorization': `Bearer ${AUTHENTIK_CONFIG.token}`,
          'Content-Type': 'application/json'
        }
      });

      try {
        await transporter.sendMail({
          from: config.smtp.from,
          to: 'admins@hackclub.app',
          subject: `${signupData.username} is awaiting review.`,
          text: `A new user has signed up and is awaiting review.\n\nName: ${signupData.name}\nUsername: ${signupData.username}\nEmail: ${signupData.email}\nSSH Key: ${authenticatedUser.sshPublicKey}`
        });
      } catch (err) {
        console.error('Failed to notify admins:', err.message);
      }

      if (config.is_production && config.new_user_script) {
        try {
          execSync(`${config.new_user_script} ${signupData.username}`);
        } catch (err) {
          console.error('Failed to run new_user.sh:', err.message);
        }
      }

      stream.write(getText('account_created', signupData.language).replace('{password}', password) + '\n');
      stream.end(getText('goodbye', signupData.language) + '\n');
    } catch (error) {
      console.error(error)
      stream.write(`Failed to create account: ${error.message}\n`);
      stream.end(getText('signup_failed', signupData.language) + '\n');
    }
  }

  async function updateName(newName) {
    try {
      await updateAuthentikAttribute(authenticatedUser.pk, 'cn', newName);
      authenticatedUser.name = newName;
      stream.write(getText('name_updated', getUserLang(authenticatedUser)) + '\n');
      showDashboard();
    } catch (err) {
      stream.write(`Failed to update name: ${err.message}\n`);
      showDashboard();
    }
  }

  async function updateEmail(newEmail) {
    try {
      verificationCode = Math.random().toString(36).substring(2, 8).toUpperCase();
      await sendVerificationEmail(newEmail, verificationCode);
      currentState = 'email_verify_code';
      stream.write(`A verification code has been sent to ${newEmail}. Enter the 6-character code to confirm your new email: `);
    } catch (err) {
      stream.write(`Failed to send verification email: ${err.message}\n`);
      showDashboard();
    }
  }

  async function updateShell(shellValue) {
    try {
      await updateAuthentikAttribute(authenticatedUser.pk, 'loginShell', shellValue);
      authenticatedUser.attributes = { ...authenticatedUser.attributes, loginShell: shellValue };
      stream.write(getText('shell_updated', getUserLang(authenticatedUser)) + '\n');
      showDashboard();
    } catch (err) {
      stream.write(`Failed to update shell: ${err.message}\n`);
      showDashboard();
    }
  }

  async function updateSSHKey(newKey) {
    try {
      await updateAuthentikAttribute(authenticatedUser.pk, 'sshPublicKey', newKey);
      authenticatedUser.sshPublicKey = newKey;
      stream.write(getText('ssh_key_updated', getUserLang(authenticatedUser)) + '\n');
      showDashboard();
    } catch (err) {
      stream.write(`Failed to update SSH Public Key: ${err.message}\n`);
      showDashboard();
    }
  }

    async function updatePassword(newPassword) {
    try {
      await axios.post(`${AUTHENTIK_CONFIG.url}/api/v3/core/users/${authenticatedUser.pk}/set_password/`, {
        password: newPassword
      }, {
        headers: {
          'Authorization': `Bearer ${AUTHENTIK_CONFIG.token}`,
          'Content-Type': 'application/json'
        }
      });

      await transporter.sendMail({
        from: config.smtp.from,
        to: authenticatedUser.email || authenticatedUser.mail,
        subject: 'Password Changed',
        text: `Hello ${authenticatedUser.name || authenticatedUser.cn},

Your password has been successfully changed. If you did not make this change, please contact admins@hackclub.app.`
      });

      stream.write(getText('password_updated', getUserLang(authenticatedUser)) + '\n');
      showDashboard();
    } catch (err) {
      stream.write(`Failed to update password: ${err.message}
`);
      showDashboard();
    }
  }

  async function updateLanguage(lang) {
    try {
      await updateAuthentikAttribute(authenticatedUser.pk, 'language', lang);
      authenticatedUser.attributes = { ...authenticatedUser.attributes, language: lang };
      stream.write(getText('language_updated', lang) + '\n');
      showDashboard();
    } catch (err) {
      stream.write(`Failed to update language: ${err.message}
`);
      showDashboard();
    }
  }

  async function generateSignupCode() {
    try {
      const code = Math.random().toString(36).substring(2, 10).toUpperCase();
      let codes = [];

      try {
        codes = JSON.parse(fs.readFileSync(codesFilePath, 'utf8'));
      } catch (err) {
        if (err.code !== 'ENOENT') {
          throw err;
        }
      }

      codes.push({ 
        code, 
        createdAt: new Date().toISOString(),
        createdBy: authenticatedUser.username || authenticatedUser.cn
      });
      fs.writeFileSync(codesFilePath, JSON.stringify(codes, null, 2));

      stream.write(getText('code_generated', getUserLang(authenticatedUser)).replace('{code}', code) + '\n');
      showDashboard();
    } catch (err) {
      stream.write(`Failed to generate signup code: ${err.message}\n`);
      showDashboard();
    }
  }

  async function listSignupCodes() {
    try {
      let codes = [];
      try {
        codes = JSON.parse(fs.readFileSync(codesFilePath, 'utf8'));
      } catch (err) {
        if (err.code !== 'ENOENT') {
          throw err;
        }
      }

      if (codes.length === 0) {
        stream.write(getText('no_codes', getUserLang(authenticatedUser)) + '\n');
      } else {
        stream.write(getText('signup_codes', getUserLang(authenticatedUser)) + ':\n');
        codes.forEach((codeEntry, index) => {
          const createdBy = codeEntry.createdBy || 'Unknown';
          const createdAt = new Date(codeEntry.createdAt).toLocaleDateString();
          stream.write(`${index + 1}. ${codeEntry.code} (Created by: ${createdBy}, Date: ${createdAt})\n`);
        });
      }
      showDashboard();
    } catch (err) {
      stream.write(`Failed to list signup codes: ${err.message}\n`);
      showDashboard();
    }
  }

  async function deleteSignupCode(codeToDelete) {
    try {
      let codes = [];
      try {
        codes = JSON.parse(fs.readFileSync(codesFilePath, 'utf8'));
      } catch (err) {
        if (err.code !== 'ENOENT') {
          throw err;
        }
      }

      const initialLength = codes.length;
      codes = codes.filter(codeEntry => codeEntry.code !== codeToDelete);
      
      if (codes.length === initialLength) {
        stream.write(getText('code_not_found', getUserLang(authenticatedUser)).replace('{code}', codeToDelete) + '\n');
      } else {
        fs.writeFileSync(codesFilePath, JSON.stringify(codes, null, 2));
        stream.write(getText('code_deleted', getUserLang(authenticatedUser)).replace('{code}', codeToDelete) + '\n');
      }
      showDashboard();
    } catch (err) {
      stream.write(`Failed to delete signup code: ${err.message}\n`);
      showDashboard();
    }
  }

  function handleData(data) {
    const input = data.toString().trim();

    if (input === 'signup' || input === 'register') {
      if (config.disable_signups) {
        stream.write(getText('signups_disabled', 'en') + '\n');
        return;
      } else {
        startSignup();
        return;
      }
    }

    const isAdmin = authenticatedUser['ak-superuser'] === 'TRUE';
    const userLang = getUserLang(authenticatedUser);
    
    if (currentState === 'menu') {
      switch (input) {
        case '1':
          currentState = 'name';
          stream.write(getText('enter_name', userLang) + ': ');
          break;
        case '2':
          currentState = 'email';
          stream.write(getText('enter_email', userLang) + ': ');
          break;
        case '3':
          currentState = 'shell';
          const currentShell = authenticatedUser.attributes?.loginShell || authenticatedUser.loginShell || getCurrentShell(authenticatedUser.username || authenticatedUser.cn);
          const availableShells = getAvailableShells();
          stream.write(`${getText('current_shell', userLang)}: ${currentShell}\n${getText('available_shells', userLang)}:\n${availableShells.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n${getText('enter_shell', userLang)}: `);
          break;
        case '4':
          currentState = 'sshkey';
          stream.write(getText('enter_ssh_key', userLang) + ': ');
          break;
        case '5':
          currentState = 'password';
          stream.write(getText('enter_password', userLang) + ': ');
          break;
        case '6':
          currentState = 'language';
          stream.write(`${getText('select_language', userLang)}:\n1. en\n2. fr\n${getText('enter_language', userLang)}: `);
          break;
        case '7':
          if (isAdmin) {
            generateSignupCode();
          } else {
            stream.end(getText('goodbye', userLang) + '\n');
          }
          break;
        case '8':
          if (isAdmin) {
            listSignupCodes();
          } else {
            stream.write(getText('invalid_choice', userLang) + '. ' + getText('choose_option', userLang) + ': ');
          }
          break;
        case '9':
          if (isAdmin) {
            currentState = 'delete_code';
            stream.write(getText('enter_code_to_delete', userLang) + ': ');
          } else {
            stream.write(getText('invalid_choice', userLang) + '. ' + getText('choose_option', userLang) + ': ');
          }
          break;
        case '10':
          if (isAdmin) {
            stream.end(getText('goodbye', userLang) + '\n');
          } else {
            stream.write(getText('invalid_choice', userLang) + '. ' + getText('choose_option', userLang) + ': ');
          }
          break;
        default:
          stream.write(getText('invalid_choice', userLang) + '. ' + getText('choose_option', userLang) + ': ');
      }
    } else if (currentState === 'select_language') {
      let lang;
      if (input === '1' || input.toLowerCase() === 'en' || input.toLowerCase() === 'english') lang = 'en';
      else if (input === '2' || input.toLowerCase() === 'fr' || input.toLowerCase() === 'français' || input.toLowerCase() === 'francais') lang = 'fr';
      else {
        stream.write('Invalid choice. Select your language / Sélectionnez votre langue:\n1. English\n2. Français\nEnter number or code: ');
        return;
      }
      signupData.language = lang;
      currentState = 'signup_confirm';
      stream.write(getText('signup_intro', lang) + ': ');
    } else if (currentState === 'signup_confirm') {
      if (['signup', 'signups', 'register', 'registration'].includes(input.toLowerCase())) {
        currentState = 'signup_code';
        stream.write(getText('have_signup_code', signupData.language) + ': ');
      } else {
        stream.write('Signup not confirmed. Goodbye.\n');
        stream.end();
      }
    } else if (currentState === 'signup_code') {
      if (input) {
        let codes = [];
        try {
          codes = JSON.parse(fs.readFileSync(codesFilePath, 'utf8'));
        } catch (err) {
          if (err.code !== 'ENOENT') {
            stream.write('Error checking code. Please try again.\n');
            return;
          }
        }
        const codeEntry = codes.find((entry) => entry.code === input);
        if (codeEntry) {
          signupData.code = input;
          stream.write(getText('valid_code', signupData.language) + '\n');
        } else {
          stream.write(getText('invalid_signup_code', signupData.language) + '\n');
        }
      }
      currentState = 'signup_name';
      stream.write(getText('enter_your_name', signupData.language) + ': ');
    } else if (currentState === 'signup_name') {
      signupData.name = input;
      currentState = 'signup_email';
      stream.write(getText('enter_your_email', signupData.language) + ': ');
    } else if (currentState === 'signup_email') {
      signupData.email = input;
      if (signupData.code) {
        currentState = 'signup_username';
        stream.write(getText('enter_username', signupData.language) + ': ');
      } else {
        axios.get(`https://identity.hackclub.com/api/external/check?email=${encodeURIComponent(signupData.email)}`)
          .then((eligibilityResponse) => {
            const result = eligibilityResponse.data.result;
            if (result === 'verified_eligible') {
              stream.write(getText('already_verified', signupData.language) + '\n');
              currentState = 'signup_username';
              stream.write(getText('enter_username', signupData.language) + ': ');
            } else {
              const message = getText(result, signupData.language) || `Unknown status: ${result}. Please visit identity.hackclub.com`;
              stream.write(`${message}\n`);
              stream.write(getText('enter_your_email', signupData.language) + ': ');
            }
          })
          .catch((error) => {
            stream.write(`Failed to check eligibility: ${error.message}\n`);
            stream.write(getText('enter_your_email', signupData.language) + ': ');
          });
      }
    } else if (currentState === 'signup_username') {
      signupData.username = input;
      validateSignup();
    } else if (currentState === 'verify_code') {
      if (input === verificationCode) {
        createAccount();
      } else {
        stream.write(getText('invalid_code', signupData.language) + ': ');
      }
    } else if (currentState === 'name') {
      updateName(input);
    } else if (currentState === 'email') {
      pendingEmail = input;
      updateEmail(pendingEmail);
    } else if (currentState === 'email_verify_code') {
      if (input === verificationCode) {
        updateAuthentikAttribute(authenticatedUser.pk, 'mail', pendingEmail)
          .then(() => {
            authenticatedUser.email = pendingEmail;
            stream.write(getText('email_updated', userLang) + '\n');
            showDashboard();
          })
          .catch((err) => {
            stream.write(`Failed to update email: ${err.message}\n`);
            showDashboard();
          });
      } else {
        stream.write('Invalid code. Enter the 6-character code sent to your new email: ');
      }
    } else if (currentState === 'shell') {
      let shellValue = input;
      const availableShells = getAvailableShells();
      const num = parseInt(input);
      if (!isNaN(num) && num >= 1 && num <= availableShells.length) {
        shellValue = availableShells[num - 1];
      }
      updateShell(shellValue);
    } else if (currentState === 'sshkey') {
      updateSSHKey(input);
    } else if (currentState === 'password') {
      updatePassword(input);
    } else if (currentState === 'delete_code') {
      deleteSignupCode(input);
    } else if (currentState === 'language') {
      let lang = input;
      const num = parseInt(input);
      if (num === 1) lang = 'en';
      else if (num === 2) lang = 'fr';
      else if (localeFiles.includes(input)) lang = input;
      else {
        stream.write(getText('invalid_choice', userLang) + '\n' + getText('choose_option', userLang) + ': ');
        return;
      }
      updateLanguage(lang);
    }
  }

  client.on('authentication', async (ctx) => {
    if (!ctx?.key) return ctx.reject();
    const publicKey = `${ctx.key?.algo} ${ctx.key?.data?.toString('base64')}`;
    try {
      const user = await searchByPublicKey(publicKey);
      if (user && user['ak-active'] === 'TRUE' && !config.all_guest_mode) {
        authenticatedUser = user;
        isSignup = false;
        ctx.accept();
      } else if (user && user['ak-active'] === 'FALSE') {
        authenticatedUser = { ...user, pending: true };
        ctx.accept();
      } else {
        isSignup = true;
        authenticatedUser = { sshPublicKey: publicKey };
        ctx.accept();
      }
    } catch (err) {
      console.error(err)
      isSignup = false;
      authenticatedUser = { sshPublicKey: publicKey };
      ctx.reject();
    }
  }).on('ready', () => {
    client.once('session', (accept) => {
      accept().once('shell', (accept) => {
        stream = accept();
        users.push(stream);

        console.log('Authenticated user:', authenticatedUser);

        if (authenticatedUser.pending) {
          stream.write(getText('pending_review', getUserLang(authenticatedUser)) + '\n');
          stream.end();
        } else if (isSignup) {
          startSignup();
        } else {
          showDashboard();
        }
        stream.on('data', handleData);
      });
    });
  }).on('close', () => {
    if (stream) {
      users.splice(users.indexOf(stream), 1);
    }
  }).on('error', (err) => {
  });
}).listen(config.port, function () {
  console.log('Listening on port ' + this.address().port);
});
