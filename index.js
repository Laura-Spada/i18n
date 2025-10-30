require('dotenv').config();

const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https');
const axios = require('axios');
const { create } = require('xmlbuilder2');

const i18n = required('i18n');

const app = express();
app.use(morgan('dev'));
app.use(cors());
app.use(express.json({ limit: '1mb' }));


i18n.configure({
  locales: ['pt', 'en'], // Idiomas suportados
  defaultLocale: 'pt', // Idioma padrão
  directory: path.join(__dirname, 'locales'), // Pasta onde estão os arquivos .json
  extension: '.json',
  logDebugFn: function (msg) {
    console.log('i18n debug:', msg);
  },
  autoReload: true, // Recarrega arquivos em desenvolvimento
  updateFiles: false, // Não gera novos arquivos automaticamente
  syncFiles: true, // Garante que todos os arquivos tenham as mesmas chaves
  cookie: 'lang', // Nome do cookie que pode ser usado para setar a linguagem
  queryParameter: 'lang', // Parâmetro de query que pode ser usado para setar linguagem
});


const PORT = process.env.PORT || 4000;
const CA_PATH = path.resolve(__dirname, '..', 'certs', 'ca', 'ca.cert.pem');
const SOAP_URL = process.env.SOAP_URL || 'https://localhost:8443/wsdl';

// HTTPS Agent confiando na CA local (gerada pelo seu script OpenSSL)
const httpsAgent = new https.Agent({
  ca: fs.existsSync(CA_PATH) ? fs.readFileSync(CA_PATH) : undefined,
  // rejectUnauthorized: false,
});

// Constrói envelope SOAP com UsernameToken e corpo SignTransactionRequest1
function buildSoapEnvelope({ username, password, transaction }) {
  const doc = create({ version: '1.0', encoding: 'UTF-8' })
    .ele('soap:Envelope', {
      'xmlns:soap': 'http://schemas.xmlsoap.org/soap/envelope/',
      'xmlns:tns': 'http://example.com/soap/SignerService',
      'xmlns:wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    })
      .ele('soap:Header')
        .ele('wsse:Security')
          .ele('wsse:UsernameToken')
            .ele('wsse:Username').txt(username).up()
            .ele('wsse:Password').txt(password).up()
          .up()
        .up()
      .up()
      .ele('soap:Body')
        .ele('tns:SignTransactionRequest')
          .ele('tns:Transaction')
            .ele('tns:Id').txt(transaction.id).up()
            .ele('tns:Payer').txt(transaction.payer).up()
            .ele('tns:Payee').txt(transaction.payee).up()
            .ele('tns:Amount').txt(String(transaction.amount)).up()
            .ele('tns:Currency').txt(transaction.currency).up()
            .ele('tns:Description').txt(transaction.description).up()
          .up()
        .up()
      .up()
    .up();
  return doc.end({ prettyPrint: true });
}

app.get('/health', (_req, res) => {
  res.json({ 
    ok: req.__('OK'),
    service: req.__('HEALTH'), 
    welcome: req.__('WELCOME'), 
    time: new Date().toISOString() });
});


app.post('/api/sign', async (req, res) => {
  try {
    const { username, password, transaction } = req.body || {};
    if (!username || !password || !transaction) {
      return res.status(400).json({ error: 'username, password e transaction são obrigatórios' });
    }

    const soapXml = buildSoapEnvelope({ username, password, transaction });

    const response = await axios.post(SOAP_URL, soapXml, {
      headers: { 'Content-Type': 'text/xml; charset=utf-8' },
      httpsAgent,
      timeout: 10000,
    });

    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    return res.status(200).send(response.data);
  } catch (err) {
    console.error('Erro /api/sign:', err);
    return res
      .status(502)
      .json({ error: 'Falha ao contatar serviço SOAP', detail: String(err.message || err) });
  }
});

app.listen(PORT, () => {
  console.log(`REST API listening on http://localhost:${PORT}`);
  console.log(`Health:       GET http://localhost:${PORT}/health`);
  console.log(`Sign:         POST http://localhost:${PORT}/api/sign`);
});
