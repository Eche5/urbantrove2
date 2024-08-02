const axios = require("axios");
const Payment = require("../models/payments");
const _ = require("lodash");
const { initializePayment, verifyPayment } =
  require("../config/paystack")(axios);

module.exports = class PaymentService {
  startPayment(data) {
    return new Promise(async (resolve, reject) => {
      try {
        const formData = _.pick(data, [
          "amount",
          "email",
          "full_name",
          "orderId",
        ]);
        formData.metadata = {
          full_name: formData.full_name,
          orderId: formData.orderId,
        };
        formData.amount *= 100;
        const response = await initializePayment(formData);
        return resolve(response.data);
      } catch (error) {
        error.source = "Start Payment Service";
        return reject(error);
      }
    });
  }
  createPayment(req) {
    const ref = req.reference;
    if (!ref) {
      return reject({ code: 400, msg: "No reference passed in query!" });
    }
    return new Promise(async (resolve, reject) => {
      try {
        const response = await verifyPayment(ref);
        const { reference, amount, status } = response.data.data;
        const { email } = response.data.data.customer;
        const { full_name, orderId } = response.data.data.metadata;
        const newPayment = {
          reference,
          amount,
          email,
          full_name,
          status,
          orderId,
        };
        const existingPayment = await Payment.findOne({ reference: reference });
        let payment;
        if (existingPayment) {
          existingPayment.status = status;
          payment = existingPayment.save();
        } else {
          payment = Payment.create(newPayment);
        }
        return resolve(payment);
      } catch (error) {
        error.source = "Create Payment Service";
        return reject(error);
      }
    });
  }
  paymentReceipt(body) {
    return new Promise(async (resolve, reject) => {
      try {
        const reference = body.reference;
        const transaction = Payment.findOne({ reference: reference });
        return resolve(transaction);
      } catch (error) {
        error.source = "Create Payment Service";
        return reject(error);
      }
    });
  }
};
