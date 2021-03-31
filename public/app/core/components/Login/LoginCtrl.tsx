import React, { PureComponent } from 'react';
import config from 'app/core/config';
import { getBackendSrv } from '@grafana/runtime';
import appEvents from 'app/core/app_events';
import { AppEvents } from '@grafana/data';

const isOauthEnabled = () => {
  return !!config.oauth && Object.keys(config.oauth).length > 0;
};

export interface FormModel {
  user: string;
  password: string;
  email: string;
  login_hint: string;
}

interface Props {
  resetCode?: string;

  children: (props: {
    isLoggingIn: boolean;
    changePassword: (pw: string) => void;
    changeLoginServiceView: (loginServiceForm: string) => void;
    isChangingPassword: boolean;
    isServiceLoginForm: string;
    skipPasswordChange: Function;
    login: (data: FormModel) => void;
    loginWithService: (data: FormModel) => void;
    disableLoginForm: boolean;
    ldapEnabled: boolean;
    authProxyEnabled: boolean;
    disableUserSignUp: boolean;
    isOauthEnabled: boolean;
    loginHint: string;
    passwordHint: string;
  }) => JSX.Element;
}

interface State {
  isLoggingIn: boolean;
  isChangingPassword: boolean;
  isServiceLoginForm: string;
}

export class LoginCtrl extends PureComponent<Props, State> {
  result: any = {};

  constructor(props: Props) {
    super(props);
    this.state = {
      isLoggingIn: false,
      isChangingPassword: false,
      isServiceLoginForm: 'none',
    };

    if (config.loginError) {
      appEvents.emit(AppEvents.alertWarning, ['Login Failed', config.loginError]);
    }
  }

  changePassword = (password: string) => {
    const pw = {
      newPassword: password,
      confirmNew: password,
      oldPassword: 'admin',
    };

    if (!this.props.resetCode) {
      getBackendSrv()
        .put('/api/user/password', pw)
        .then(() => {
          this.toGrafana();
        })
        .catch((err: any) => console.error(err));
    }

    const resetModel = {
      code: this.props.resetCode,
      newPassword: password,
      confirmPassword: password,
    };

    getBackendSrv()
      .post('/api/user/password/reset', resetModel)
      .then(() => {
        this.toGrafana();
      });
  };

  login = (formModel: FormModel) => {
    this.setState({
      isLoggingIn: true,
    });

    getBackendSrv()
      .post('/login', formModel)
      .then((result: any) => {
        this.result = result;
        if (formModel.password !== 'admin' || config.ldapEnabled || config.authProxyEnabled) {
          this.toGrafana();
          return;
        } else {
          this.changeView();
        }
      })
      .catch(() => {
        this.setState({
          isLoggingIn: false,
        });
      });
  };

  loginWithService = (formModel: FormModel) => {
    this.setState({
      isLoggingIn: true,
    });

    getBackendSrv()
      .get('/login/service/' + this.state.isServiceLoginForm + '/lookup/' + formModel.login_hint, formModel)
      .then((result: any) => {
        this.result = result;
        window.location.href =
          config.appSubUrl + '/login/' + this.state.isServiceLoginForm + '/?login_hint=' + formModel.login_hint;
        this.setState({
          isLoggingIn: false,
          isChangingPassword: false,
          isServiceLoginForm: 'none',
        });
      })
      .catch(() => {
        this.setState({
          isLoggingIn: false,
        });
      });
    /**window.location.href = config.appSubUrl + '/login/' + this.state.isServiceLoginForm + '/?login_hint=hardcoced';
    this.setState({
      isLoggingIn: false,
      isChangingPassword: false,
      isServiceLoginForm: 'none',
    });*/
  };

  changeView = () => {
    this.setState({
      isChangingPassword: true,
    });
  };

  changeLoginServiceView = (loginServiceForm: string) => {
    this.setState({
      isServiceLoginForm: loginServiceForm,
    });
  };

  toGrafana = () => {
    // Use window.location.href to force page reload
    if (this.result.redirectUrl) {
      if (config.appSubUrl !== '' && !this.result.redirectUrl.startsWith(config.appSubUrl)) {
        window.location.href = config.appSubUrl + this.result.redirectUrl;
      } else {
        window.location.href = this.result.redirectUrl;
      }
    } else {
      window.location.href = config.appSubUrl + '/';
    }
  };

  render() {
    const { children } = this.props;
    const { isLoggingIn, isChangingPassword, isServiceLoginForm } = this.state;
    const { login, loginWithService, toGrafana, changePassword, changeLoginServiceView } = this;
    const { loginHint, passwordHint, disableLoginForm, ldapEnabled, authProxyEnabled, disableUserSignUp } = config;

    return (
      <>
        {children({
          isOauthEnabled: isOauthEnabled(),
          loginHint,
          passwordHint,
          disableLoginForm,
          ldapEnabled,
          authProxyEnabled,
          disableUserSignUp,
          login,
          loginWithService,
          isLoggingIn,
          changePassword,
          changeLoginServiceView,
          skipPasswordChange: toGrafana,
          isChangingPassword,
          isServiceLoginForm,
        })}
      </>
    );
  }
}

export default LoginCtrl;
