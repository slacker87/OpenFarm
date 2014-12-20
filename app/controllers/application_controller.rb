class ApplicationController < ActionController::Base
  include Pundit
  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized
  rescue_from Mongoid::Errors::DocumentNotFound, with: :record_not_found
  protect_from_forgery with: :exception
  helper_method :current_or_guest_user

  # Allow certain fields for devise - needed in Rails 4.0+
  before_filter :update_sanitized_params, if: :devise_controller?

  before_action :set_locale

  def default_url_options(options = {})
    { locale: I18n.locale }
  end

  def set_locale
    I18n.locale = params[:locale] || I18n.default_locale
  end

  # if user is logged in, return current_user, else return guest_user
  def current_or_guest_user
    if current_user
      if session[:guest_user_id] && session[:guest_user_id] != current_user.id
        logging_in
        guest_user(with_retry = false).try(:destroy)
        session[:guest_user_id] = nil
      end
      current_user
    else
      guest_user
    end
  end

  # find guest_user object associated with the current session,
  # creating one as needed
  def guest_user(with_retry = true)
    # Cache the value the first time it's gotten.
    @cached_guest_user ||= User.find(session[:guest_user_id] ||= create_guest_user.id) rescue nil

    if @cached_guest_user.nil?
     session[:guest_user_id] = nil
     guest_user if with_retry
    end
  end

  #THIS WILL REPLACE current_user HELPER WITH ONE THAT AUTO-CREATES A GUEST USER
  #NAVIGATION ETC WILL NEED TO BE CHANGED TO DENY GUEST USERS ACCESS TO PROFILE PAGES BEFORE THIS IS USED
  #alias_method :devise_current_user, :current_user
  #def current_user
  #  if devise_current_user
  #    if session[:guest_user_id] && session[:guest_user_id] != devise_current_user.id
  #      logging_in
  #      guest_user(with_retry = false).try(:destroy)
  #      session[:guest_user_id] = nil
  #    end
  #    devise_current_user
  #  else
  #    guest_user
  #  end
  #end

  protected

  # This method allows devise to pass non standard attributes through and
  # thereby comply with 'strong parameters'.
  def update_sanitized_params
    devise_parameter_sanitizer.for(:sign_up) do |params|
      params.permit *safe_user_attrs
    end

    devise_parameter_sanitizer.for(:account_update) do |params|
      params.permit *(safe_user_attrs << :current_password)
    end
  end

  # List of attributes that are safe for mass assignment on User objects.
  def safe_user_attrs
    [:display_name, :email, :location, :password, :units,
     :years_experience, :mailing_list, :is_private]
  end

  def current_admin
    if current_user && current_user.admin?
      return current_user
    else
      flash[:notice] = 'I told you kids to get out of here!'
      redirect_to '/' and return
    end
  end

  private

  def record_not_found
    render file: "#{Rails.root}/public/404",
           formats: [:html],
           status: 404,
           layout: false
  end

  def user_not_authorized
    flash[:alert] = "Woops, that's not a page!"
    redirect_to(request.referrer || root_path)
  end

  # called (once) when the user logs in, insert any code your application needs
  # to hand off from guest_user to current_user.
  def logging_in
    # For example:
    # guest_comments = guest_user.comments.all
    # guest_comments.each do |comment|
      # comment.user_id = current_user.id
      # comment.save!
    # end
  end

  def create_guest_user
    u = Users::UpdateUser.run(:display_name => "guest", :email => "guest_#{Time.now.to_i}#{rand(100)}@guest.com")
    session[:guest_user_id] = u.id
    u
  end
end
