const User = require("../models/user");
const bcrypt = require("bcryptjs");

// module.exports = {
//   hello() {
//     return {
//       text: "Hello World!",
//       views: 1234,
//     };
//   },
// };

module.exports = {
  createUser: async function ({ userInput }, req) {
    const existingUser = await User.findOne({ email: userInput.email });

    if (existingUser) {
      const error = new Error("user already exists");

      throw error;
    }

    const hashedPassword = await bcrypt.hash(userInput.password, 12);
    const user = new User({
      email: userInput.email,
      name: userInput.name,
      password: hashedPassword,
    });

    const createdUser = await user.save();
    return { ...createdUser._doc, _id: createdUser._id.toString() };
  },
};