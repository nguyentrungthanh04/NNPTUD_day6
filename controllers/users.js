let userModel = require('../schemas/users')
module.exports = {
    CreateAnUser: async function (
        username, password, email, role, fullname, avatarUrl, status, loginCount) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullname,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        });
        await newUser.save();
        return newUser;
    },
    FindUserByUsername: async function (username) {
        return await userModel.findOne({
            username: username,
            isDeleted: false
        })
    },
    FindUserById: async function (id) {
        try {
            return await userModel.findOne({
                _id: id,
                isDeleted: false
            })
        } catch (error) {
            return false
        }
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        let user = await userModel.findOne({ _id: userId, isDeleted: false });
        if (!user) {
            throw new Error("User not found");
        }
        let bcrypt = require('bcrypt');
        let isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            throw new Error("oldpassword khong dung");
        }
        user.password = newPassword;
        await user.save();
        return { message: "doi mat khau thanh cong" };
    }
}