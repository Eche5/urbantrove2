exports.sendMailer = (
  optionsTransporterMail = OptionsTransporterMail,
  optionsMail = OptionsMail,
  callback
) => {
  const nodemailer = require("nodemailer");

  let transporter = nodemailer.createTransport(optionsTransporterMail);

  transporter.sendMail(optionsMail, function (err, info) {
    callback(err, info);
  });
};

sendMailer(
  {
    service: "mail.mywebsite.com",
    port: 465,
    secure: true,
    auth: {
      user: "contact@mywebsite.com",
      pass: "12345678",
    },
  },
  {
    from: '"My app <contact@mywebsite.com>',
    to: "echendu0803@gnail.com",
    subject: "Notify",
    text: "Hello worlds",
    html: "Hello worlds",
  },
  (err, info) => {
    console.log(info);
  }
);
