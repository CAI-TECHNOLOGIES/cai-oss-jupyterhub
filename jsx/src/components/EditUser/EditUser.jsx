import React, { useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import PropTypes from "prop-types";
import { Link } from "react-router-dom";

const EditUser = (props) => {
  const apis = props.apis
  var limit = useSelector((state) => state.limit),
    [errorAlert, setErrorAlert] = useState(null);

  var dispatch = useDispatch();

  var dispatchPageChange = (data, page) => {
    dispatch({
      type: "USER_PAGE",
      value: {
        data: data,
        page: page,
      },
    });
  };

  var { editUser, deleteUser, noChangeEvent, updateUsers, history } = apis;

  if (apis.location.state == undefined) {
    apis.history.push("/");
    return <></>;
  }

  var { username, has_admin } = apis.location.state;

  var [updatedUsername, setUpdatedUsername] = useState(""),
    [admin, setAdmin] = useState(has_admin);

  return (
    <>
      <div className="container" data-testid="container">
        {errorAlert != null ? (
          <div className="row">
            <div className="col-md-10 col-md-offset-1 col-lg-8 col-lg-offset-2">
              <div className="alert alert-danger">
                {errorAlert}
                <button
                  type="button"
                  className="close"
                  onClick={() => setErrorAlert(null)}
                >
                  <span>&times;</span>
                </button>
              </div>
            </div>
          </div>
        ) : (
          <></>
        )}
        <div className="row">
          <div className="col-md-10 col-md-offset-1 col-lg-8 col-lg-offset-2">
            <div className="panel panel-default">
              <div className="panel-heading">
                <h4>Editing user {username}</h4>
              </div>
              <div className="panel-body">
                <form>
                  <div className="form-group">
                    <textarea
                      className="form-control"
                      data-testid="edit-username-input"
                      id="exampleFormControlTextarea1"
                      rows="3"
                      placeholder="updated username"
                      onBlur={(e) => {
                        setUpdatedUsername(e.target.value);
                      }}
                    ></textarea>
                    <br></br>
                    <input
                      className="form-check-input"
                      checked={admin}
                      type="checkbox"
                      id="admin-check"
                      onChange={() => setAdmin(!admin)}
                    />
                    <span> </span>
                    <label className="form-check-label">Admin</label>
                    <br></br>
                    <button
                      id="delete-user"
                      data-testid="delete-user"
                      className="btn btn-danger btn-sm"
                      onClick={(e) => {
                        e.preventDefault();
                        deleteUser(username)
                          .then((data) => {
                            data.status < 300
                              ? updateUsers(0, limit)
                                  .then((data) => dispatchPageChange(data, 0))
                                  .then(() => history.push("/"))
                                  .catch(() =>
                                    setErrorAlert(
                                      `Could not update users list.`
                                    )
                                  )
                              : setErrorAlert(`Failed to edit user.`);
                          })
                          .catch(() => {
                            setErrorAlert(`Failed to edit user.`);
                          });
                      }}
                    >
                      Delete user
                    </button>
                  </div>
                </form>
              </div>
              <div className="panel-footer">
                <button className="btn btn-light">
                  <Link to="/">Back</Link>
                </button>
                <span> </span>
                <button
                  id="submit"
                  data-testid="submit"
                  className="btn btn-primary"
                  onClick={(e) => {
                    e.preventDefault();
                    if (updatedUsername == "" && admin == has_admin) {
                      noChangeEvent();
                      return;
                    } else if (updatedUsername != "") {
                      if (
                        updatedUsername.length > 2 &&
                        /[!@#$%^&*(),.?":{}|<>]/g.test(updatedUsername) == false
                      ) {
                        editUser(
                          username,
                          updatedUsername != "" ? updatedUsername : username,
                          admin
                        )
                          .then((data) => {
                            data.status < 300
                              ? updateUsers(0, limit)
                                  .then((data) => dispatchPageChange(data, 0))
                                  .then(() => history.push("/"))
                                  .catch(() =>
                                    setErrorAlert(
                                      `Could not update users list.`
                                    )
                                  )
                              : setErrorAlert(`Failed to edit user.`);
                          })
                          .catch(() => {
                            setErrorAlert(`Failed to edit user.`);
                          });
                      } else {
                        setErrorAlert(
                          `Failed to edit user. Make sure the username does not contain special characters.`
                        );
                      }
                    } else {
                      editUser(username, username, admin)
                        .then((data) => {
                          data.status < 300
                            ? updateUsers(0, limit)
                                .then((data) => dispatchPageChange(data, 0))
                                .then(() => history.push("/"))
                                .catch(() =>
                                  setErrorAlert(`Could not update users list.`)
                                )
                            : setErrorAlert(`Failed to edit user.`);
                        })
                        .catch(() => {
                          setErrorAlert(`Failed to edit user.`);
                        });
                    }
                  }}
                >
                  Apply
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default EditUser;
