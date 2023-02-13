const fs = require("fs/promises");
const crypto = require("crypto");
const path = require("path");
const util = require("util");
const exec = util.promisify(require("child_process").exec);

/**
 * Encrypts a given string using the RSA public key at the specified file path.
 * 
 * @param {string} toEncrypt - The string to be encrypted.
 * @param {string} publicKeyPath - The relative or absolute path to the RSA public key file.
 * 
 * @returns {string|null} - The encrypted string in base64 format, or `null` if encryption failed.
 */
const encryptStringWithRsaPublicKey = async (toEncrypt, publicKeyPath) => {
    try {
      const absolutePath = path.resolve(publicKeyPath);
      const publicKey = await fs.readFile(absolutePath, "utf8");
      const buffer = Buffer.from(toEncrypt);
      const encrypted = crypto.publicEncrypt(publicKey, buffer);
      return encrypted.toString("base64");
    } catch (error) {
      logger.error(error);
      return null;
    }
};
/**
 * Decrypts a given string in base64 format using the RSA private key at the specified file path.
 * 
 * @param {string} toDecrypt - The string to be decrypted in base64 format.
 * @param {string} privateKeyPath - The relative or absolute path to the RSA private key file.
 * 
 * @returns {string|null} - The decrypted string, or `null` if decryption failed.
 */
const decryptStringWithRsaPrivateKey = async (toDecrypt, privateKeyPath) => {
    try {
      const absolutePath = path.resolve(privateKeyPath);
      const privateKey = await fs.readFile(absolutePath, "utf8");
      const buffer = Buffer.from(toDecrypt, "base64");
      const decrypted = crypto.privateDecrypt(privateKey, buffer);
      return decrypted.toString("utf8");
    } catch (error) {
      logger.error(error);
      return null;
    }
};

const logger = {};
 /**
   * Writes message to process.stdout
   * @param {string} message - The message to write to process.stdout
   * @param {string} [type='info'] - Type of message (info, success, error)
   */
logger.info = (message, type = 'info') => {
    process.stdout.write(`[${type.toUpperCase()}]: ${message}\n`);
}

  /**
   * Writes message to process.stderr
   * @param {string} message - The message to write to process.stderr
   * @param {string} [type='error'] - Type of message (error, warning)
   */
logger.error = (message, type = 'error') => {
    process.stdout.write(`[${type.toUpperCase()}]: ${message}\n`);
}

(async () => {
    try {
        const argv = process.argv;
        const command = argv[2];
        const options = argv.reduce((acc, val, index) => {
            if (index >= 3) {
                if (val.startsWith("-")) {
                    acc[val.replace('-', '')] = argv[index + 1];
                }
            }
            return acc;
        }, {});

        const help = `
Usage: env-tool <command> [OPTIONS]

Commands:
    -e, --encrypt  Encrypt the .env file using RSA encryption
    -d, --decrypt  Decrypt the env.json file using RSA decryption
    -k, --keygen   Generate RSA public/private keys for encryption/decryption
    -h, --help     Display help information and usage options

Options:
    -i, --input <filepath>     Input file path. The default input file path is env.json.
    -p, --public <filepath>    RSA public key file path. The default path is .keys/rsa_public.pem.
    -k, --private <filepath>   RSA private key file path. The default path is .keys/rsa_private.pem.
    -o, --output <filepath>    Output file path. The default output file path is .env.

To run the commands:

    1. Encrypt the env.json file to .env:
        env-tool encrypt -i env.json -p .keys/rsa_public.pem -o .env

    2. Decrypt the .env file to env.json:
        env-tool decrypt -i .env -k .keys/rsa_private.pem -o env.json

    3. Generate RSA public/private keys for encryption/decryption:
        env-tool keygen -o .keys

Example:
    env-tool encrypt -i env.json -p .keys/rsa_public.pem -o .env
    env-tool decrypt -i .env -k .keys/rsa_private.pem -o env.json
    env-tool keygen -o .keys

Note: The RSA encryption and decryption uses public/private key pair. The keys should be generated and kept securely to ensure the security of the encrypted files.\n`;
        if (['help', '--help', -'h'].indexOf(command) > -1 || !command) {
            logger.info(help);
            return;
        } else if (['encrypt', '--encrypt', '-e'].indexOf(command) > -1) {
            const input = (options.i || options.input) || './env.json';
            let env;
            try {
                env = await fs.readFile(input);
                env = JSON.parse(env);
            } catch (error) {
                logger.error(`Error reading file '${input}': ${error}\n`);
                return;
            }
            const publickey = (options.p || options.public) || './.keys/rsa_public.pem'
            for (const key of Object.keys(env)) {
                env[key] = await encryptStringWithRsaPublicKey(env[key], publickey) || env[key];
            }
            let encryptedEnv = '';
            for (const [key, value] of Object.entries(env)) {
                encryptedEnv = encryptedEnv.concat(`${key}=${value}\n`);
            }
            const output = (options.o || options.output) || '.env';
            try {
                await fs.writeFile(output, encryptedEnv);
            } catch (error) {
                logger.error(`Error writing file '${output}': ${error}\n`);
                return;
            }
            logger.info(`Successfully encrypted ${input} with key ${publickey} to ${output}\n`);
        } else
            if (['decrypt', '--decrypt', '-d'].includes(command)) {
                const input = (options.i || options.input) || '.env';
                const privateKey = (options.k || options.private) || './.keys/rsa_private.pem'
                const env = await fs.readFile(input, 'utf8');
                const lines = env.split('\n');
                let decryptedEnv = {};
                for (const line of lines) {
                    const [key, value] = line.split('=');
                    if (key && value && !/^\s*$/.test(line)) {
                        decryptedEnv[key.trim().replace(/["]/g, '')] = await decryptStringWithRsaPrivateKey(value.trim().replace(/["]/g, ''), privateKey) || value;
                    }
                }
                const output = (options.o || options.output) || 'env.json';
                await fs.writeFile(output, JSON.stringify(decryptedEnv, null, 2));
                logger.info(`Successfully decrypted ${input} with key ${privateKey} to ${output}`);
            } else if (['keygen', '--keygen', '-k'].includes(command)) {
                const outputDir = (options.o || options.output) || '.keys';
                if (!outputDir || /^\s*$/.test(outputDir)) {
                    logger.error(`Invalid argument for output-dir '${outputDir}'`);
                    return;
                }
                try {
                    await exec(`mkdir -p ${outputDir}`);
                    await exec(`openssl genpkey -algorithm RSA -out ${outputDir}/rsa_private.pem -pkeyopt rsa_keygen_bits:2048`);
                    logger.info(`Private key saved at: ${outputDir}/rsa_private.pem`);
                    await exec(`openssl rsa -in ${outputDir}/rsa_private.pem -pubout -out ${outputDir}/rsa_public.pem`);
                    logger.info(`Public key saved at: ${outputDir}/rsa_public.pem`);
                } catch (error) {
                    logger.error(`OpenSSL installation not found: ${error}`);
                }
            } else {
                logger.error(`No command provided.\nAvailable ${help}`);
            }
    } catch (e) {
        logger.error(`could not encrypt/decrypt with provided parameters\n${e}`);
    }
})();
