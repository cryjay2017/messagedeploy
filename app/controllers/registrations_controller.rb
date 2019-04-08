class RegistrationsController < Devise::RegistrationsController
  def update
    new_params = params.require(:user).permit(:email,
    :username, :current_password, :password,
    :password_confirmation)
    @user = User.find(current_user.id)
    if @user.update_with_password(new_params)
      set_flash_message :notice, :updated
      sign_in @user, :bypass => true
      redirect_to after_update_path_for(@user), notice: "用户修改密码成功"
    else
      render "edit"
    end
  end
end