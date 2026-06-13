const mongoose = require("mongoose");

const TradeHistorySchema = new mongoose.Schema(
{
  account: {
    type: String,
    required: true,
    index: true
  },

  ticket: {
    type: Number,
    required: true
  },

  symbol: String,

  type: String,

  volume: Number,

  profit: Number,

  closeTime: Date
},
{
  timestamps: true
});

TradeHistorySchema.index(
  {
    account: 1,
    ticket: 1
  },
  {
    unique: true
  }
);

module.exports =
  mongoose.model(
    "TradeHistory",
    TradeHistorySchema
  );