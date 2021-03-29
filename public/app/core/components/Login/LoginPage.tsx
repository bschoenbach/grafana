// Libraries
import React, { FC } from 'react';
import { css } from 'emotion';

// Components
import { UserSignup } from './UserSignup';
import { LoginServiceButtons } from './LoginServiceButtons';
import LoginCtrl from './LoginCtrl';
import { LoginForm } from './LoginForm';
import { ChangePassword } from '../ForgottenPassword/ChangePassword';
import { Branding } from 'app/core/components/Branding/Branding';
import { HorizontalGroup, LinkButton } from '@grafana/ui';
import { LoginLayout, InnerBox } from './LoginLayout';
import config from 'app/core/config';
import { LoginFormID4me } from './LoginServiceForms';

const forgottenPasswordStyles = css`
  padding: 0;
  margin-top: 4px;
`;

export const LoginPage: FC = () => {
  document.title = Branding.AppTitle;
  return (
    <LoginLayout>
      <LoginCtrl>
        {({
          loginHint,
          passwordHint,
          ldapEnabled,
          authProxyEnabled,
          disableLoginForm,
          disableUserSignUp,
          login,
          isLoggingIn,
          changePassword,
          changeLoginServiceView,
          skipPasswordChange,
          isChangingPassword,
          isServiceLoginForm,
        }) => (
          <>
            {isServiceLoginForm !== 'none' && (
              <InnerBox>
                {isServiceLoginForm === 'id4me' && (
                  <>
                    <LoginFormID4me
                      onSubmit={login}
                      loginHint={loginHint}
                      passwordHint={passwordHint}
                      isLoggingIn={isLoggingIn}
                    >
                      <></>
                    </LoginFormID4me>
                  </>
                )}
              </InnerBox>
            )}
            {!isChangingPassword && isServiceLoginForm === 'none' && (
              <InnerBox>
                {!disableLoginForm && (
                  <>
                    <LoginForm
                      onSubmit={login}
                      loginHint={loginHint}
                      passwordHint={passwordHint}
                      isLoggingIn={isLoggingIn}
                    >
                      {!(ldapEnabled || authProxyEnabled) ? (
                        <HorizontalGroup justify="flex-end">
                          <LinkButton
                            className={forgottenPasswordStyles}
                            variant="link"
                            href={`${config.appSubUrl}/user/password/send-reset-email`}
                          >
                            Forgot your password?
                          </LinkButton>
                        </HorizontalGroup>
                      ) : (
                        <></>
                      )}
                    </LoginForm>
                  </>
                )}
                <LoginServiceButtons changeLoginServiceView={changeLoginServiceView} />
                {!disableUserSignUp && <UserSignup />}
              </InnerBox>
            )}
            {isChangingPassword && isServiceLoginForm === 'none' && (
              <InnerBox>
                <ChangePassword onSubmit={changePassword} onSkip={() => skipPasswordChange()} />
              </InnerBox>
            )}
          </>
        )}
      </LoginCtrl>
    </LoginLayout>
  );
};
