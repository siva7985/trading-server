const mongoose = require("mongoose");

const EAActivationSchema = new mongoose.Schema({

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  account: {
    type: String,
    required: true
  },

  eaId: {
    type: String,
    required: true
  },

  status: {
    type: String,
    default: "active"
  },

  settings: {
    lot: {
      type: Number,
      default: 0.01
    },

    risk: {
      type: Number,
      default: 1
    }
  }

}, {
  timestamps: true
});

module.exports = mongoose.model(
  "EAActivation",
  EAActivationSchema
);